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
	SetDefault(model *Model) error
	Credential(model *Model, profile string) (*Credential, error)
	Config(model *Model, profile string) (*Config, error)
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
	Name         string
	AccessKey    string
	SecretKey    string
	SessionToken string
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

func (p *profile) Credential(model *Model, profile string) (*Credential, error) {
	if profile == "default" {
		return model.Credentials[0], nil
	}
	for _, c := range model.Credentials {
		if c.Name == profile {
			return c, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("profile not found. [%s]", profile))
}

func (p *profile) Config(model *Model, profile string) (*Config, error) {
	if profile == "default" {
		return model.Configs[0], nil
	}
	for _, c := range model.Configs {
		if c.Name == fmt.Sprintf("profile %s", profile) {
			return c, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("profile not found. [%s]", profile))
}

func (p *profile) SetDefault(model *Model) error {
	configPath, crePath, err := p.profilePath()
	if err != nil {
		return errors.WithStack(err)
	}

	if err := p.writeConfig(configPath, model); err != nil {
		return errors.WithStack(err)
	}

	if err := p.writeCredential(crePath, model); err != nil {
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

func (p *profile) writeConfig(fpath string, model *Model) error {
	tConfig, err := p.tomlConfigs(model.Configs)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := p.toml.WriteFile(fpath, tConfig); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (p *profile) writeCredential(fpath string, model *Model) error {
	tCredential, err := p.tomlCredentials(model.Credentials)
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
		var configs = []*toml.Config{
			{
				Key:   "aws_access_key_id",
				Value: cre.AccessKey,
			},
			{
				Key:   "aws_secret_access_key",
				Value: cre.SecretKey,
			},
		}
		if cre.SessionToken != "" {
			configs = append(configs, &toml.Config{
				Key:   "aws_session_token",
				Value: cre.SessionToken,
			})
		}

		t.Tables[i] = &toml.Table{
			Name:    cre.Name,
			Configs: configs,
		}
	}
	return t, nil
}
