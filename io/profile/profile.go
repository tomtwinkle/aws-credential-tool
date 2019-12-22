package profile

import (
	"aws-credential-tool/io/toml"
	"fmt"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"path/filepath"
)

type Profile interface {
	Load() (*Model, error)
	SetDefault(model *Model, profile string) error
}

type profile struct {
	toml toml.Toml
}

type Model struct {
	Configs     []*Config
	Credentials []*Credential
}

type Config struct {
	Name   string
	Region string
	Output string
}

type Credential struct {
	Name      string
	AccessKey string
	SecretKey string
}

func NewProfile() Profile {
	t := toml.NewToml()
	return &profile{toml: t}
}

func (p *profile) Load() (*Model, error) {
	configPath, crePath, err := p.profilePath()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	tomlModel, err := p.toml.DecodeFile(configPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	configs, err := p.mappingConfigs(tomlModel)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	tomlModel, err = p.toml.DecodeFile(crePath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	credentials, err := p.mappingCredentials(tomlModel)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &Model{
		Configs:     configs,
		Credentials: credentials,
	}, nil
}

func (p *profile) SetDefault(model *Model, profile string) error {
	if profile == "default" {
		return nil
	}

	configPath, crePath, err := p.profilePath()
	if err != nil {
		return errors.WithStack(err)
	}

	if err := p.writeConfig(configPath, model, profile); err != nil {
		return errors.WithStack(err)
	}

	if err := p.writeCredential(crePath, model, profile); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (p *profile) profilePath() (string, string, error) {
	homeDir, err := homedir.Dir()
	if err != nil {
		return "", "", errors.WithStack(err)
	}

	configPath := filepath.Join(homeDir, ".aws", "config")
	credentialsPath := filepath.Join(homeDir, ".aws", "credentials")

	return configPath, credentialsPath, nil
}

func (p *profile) mappingConfigs(t *toml.Model) ([]*Config, error) {
	if t == nil {
		return nil, errors.New("toml model of nil")
	}
	var configs = make([]*Config, len(t.Tables))
	for idx, table := range t.Tables {
		var region, output string
		regionConfig, ok := table.Config("region")
		if ok {
			region = regionConfig
		}
		outputConfig, ok := table.Config("output")
		if ok {
			output = outputConfig
		}

		configs[idx] = &Config{
			Name:   table.Name,
			Region: region,
			Output: output,
		}
	}
	return configs, nil
}

func (p *profile) mappingCredentials(t *toml.Model) ([]*Credential, error) {
	if t == nil {
		return nil, errors.New("toml model of nil")
	}
	var credentials = make([]*Credential, len(t.Tables))
	for idx, table := range t.Tables {
		var accessKey, secretKey string
		accessKeyConfig, ok := table.Config("aws_access_key_id")
		if ok {
			accessKey = accessKeyConfig
		}
		secretKeyConfig, ok := table.Config("aws_secret_access_key")
		if ok {
			secretKey = secretKeyConfig
		}

		credentials[idx] = &Credential{
			Name:      table.Name,
			AccessKey: accessKey,
			SecretKey: secretKey,
		}
	}
	return credentials, nil
}

func (p *profile) writeConfig(fpath string, model *Model, profile string) error {
	var wConfigs = make([]*Config, len(model.Configs))
	for i := 1; i < len(model.Configs); i++ {
		config := model.Configs[i]
		wConfigs[i] = config
		if config.Name == fmt.Sprintf("profile %s", profile) {
			wConfigs[0] = &Config{
				Name:   "default",
				Region: config.Region,
				Output: config.Output,
			}
		}
	}

	tConfig, err := p.tomlConfigs(wConfigs)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := p.toml.WriteFile(fpath, tConfig); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (p *profile) writeCredential(fpath string, model *Model, profile string) error {
	var wCredentials = make([]*Credential, len(model.Credentials))
	for i := 1; i < len(model.Credentials); i++ {
		credential := model.Credentials[i]
		wCredentials[i] = credential
		if credential.Name == profile {
			wCredentials[0] = &Credential{
				Name:      "default",
				AccessKey: credential.AccessKey,
				SecretKey: credential.SecretKey,
			}
		}
	}
	tCredential, err := p.tomlCredentials(wCredentials)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := p.toml.WriteFile(fpath, tCredential); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (p *profile) tomlConfigs(configs []*Config) (*toml.Model, error) {
	if configs == nil {
		return nil, errors.New("configs model of nil")
	}
	var t = new(toml.Model)
	t.Tables = make([]*toml.Table, len(configs))
	for i, config := range configs {
		if config == nil {
			continue
		}
		t.Tables[i] = &toml.Table{
			Name: config.Name,
			Configs: []*toml.Config{
				{
					Key:   "region",
					Value: config.Region,
				},
				{
					Key:   "output",
					Value: config.Output,
				},
			},
		}
	}
	return t, nil
}

func (p *profile) tomlCredentials(credentials []*Credential) (*toml.Model, error) {
	if credentials == nil {
		return nil, errors.New("credentials model of nil")
	}
	var t = new(toml.Model)
	t.Tables = make([]*toml.Table, len(credentials))
	for i, cre := range credentials {
		t.Tables[i] = &toml.Table{
			Name: cre.Name,
			Configs: []*toml.Config{
				{
					Key:   "aws_access_key_id",
					Value: cre.AccessKey,
				},
				{
					Key:   "aws_secret_access_key",
					Value: cre.SecretKey,
				},
			},
		}
	}
	return t, nil
}
