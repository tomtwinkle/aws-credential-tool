package ui

import (
	"errors"

	"github.com/tomtwinkle/aws-credential-tool/internal/errguide"
	"github.com/tomtwinkle/aws-credential-tool/io/profile"
	"github.com/tomtwinkle/aws-credential-tool/ui/mode"
	"github.com/tomtwinkle/aws-credential-tool/ui/model"
)

type UI interface {
	Run() error
}

type ui struct {
	mProfile *profile.Model
	nextMode model.SelectMode
	mode     model.SelectMode

	profile profile.Profile

	profileSelect mode.ProfileSelect
	actionSelect  mode.ActionSelect

	selectProfile    string
	selectCredential *profile.Credential
	selectConfig     *profile.Config
}

func NewUI() (UI, error) {
	initMode := model.SelectModeProfileSelect
	p, err := profile.NewInteractiveProfile(promptDeleteLegacyCredentials)
	if err != nil {
		return nil, errguide.Wrap(err,
			"Unlock or configure an AWS-compatible keyring, then run actool again.",
			"Alternatively configure the encrypted file backend with AWS_VAULT_BACKEND=file.",
		)
	}

	mProfile, err := p.Load()
	if err != nil {
		return nil, errguide.Wrap(err,
			"Verify AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE if custom paths are in use.",
			"Fix the reported profile or configuration issue, then run actool again.",
		)
	}
	if mProfile == nil || len(mProfile.Credentials) == 0 {
		return nil, errguide.New("Profile not defined.",
			"Add a profile directly to the secure store with `aws-vault add <profile>`.",
			"Or create `~/.aws/credentials` with `aws configure --profile <profile>` and run actool.",
			"Run actool again after at least one profile is available.",
		) //nolint:staticcheck // preserve the existing user-facing error text
	}
	profileSelect := mode.NewModeProfileSelect(mProfile)
	actionSelect := mode.NewModeActionSelect()

	return &ui{
		profileSelect: profileSelect,
		actionSelect:  actionSelect,
		profile:       p,
		nextMode:      initMode,
		mProfile:      mProfile,
	}, nil
}

func (u *ui) Run() error {
	for {
		exit, err := u.render()
		if err != nil {
			return err
		}
		if exit {
			return nil
		}
	}
}

func (u *ui) render() (bool, error) {
	if u.nextMode == u.mode {
		return false, nil
	}

	switch u.nextMode {
	case model.SelectModeProfileSelect:
		if err := u.modeProfileSelect(); err != nil {
			return false, err
		}
	case model.SelectModeActionSelect:
		if err := u.modeActionSelect(); err != nil {
			return false, err
		}
	case model.SelectModeSTS:
		if err := u.modeSTS(); err != nil {
			return false, err
		}
	case model.SelectModeEnd:
		u.mode = model.SelectModeEnd
		if err := u.profile.SetSelected(u.selectProfile); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, errors.New("Undefined mode.") //nolint:staticcheck // preserve the existing user-facing error text
	}
	return false, nil
}

func (u *ui) modeProfileSelect() error {
	u.mode = model.SelectModeProfileSelect
	profileStr, err := u.profileSelect.Select()
	if err != nil {
		return err
	}
	if profileStr == "" {
		return errguide.New("not select profile.",
			"Use the arrow keys to select a profile and press Enter.",
			"Run actool again if the profile list is empty.",
		) //nolint:staticcheck // preserve the existing error text
	}
	cre, err := u.profile.Credential(profileStr)
	if err != nil {
		return err
	}
	conf, err := u.profile.Config(u.mProfile, profileStr)
	if err != nil {
		return err
	}

	u.selectProfile = profileStr
	u.selectCredential = cre
	u.selectConfig = conf

	u.nextMode = model.SelectModeActionSelect
	return nil
}

func (u *ui) modeActionSelect() error {
	u.mode = model.SelectModeActionSelect
	nextMode, err := u.actionSelect.Select()
	if err != nil {
		return err
	}
	u.nextMode = nextMode
	return nil
}

func (u *ui) modeSTS() error {
	u.mode = model.SelectModeSTS
	sts := mode.NewModeSTSWithMFASerial(u.selectCredential.AccessKey, u.selectCredential.SecretKey, u.selectConfig.Region, u.selectConfig.MFASerial)
	sToken, err := sts.GetSessionToken()
	if err != nil {
		return err
	}
	cre := &profile.Credential{
		Name:         u.selectProfile,
		AccessKey:    sToken.AccessKey,
		SecretKey:    sToken.SecretKey,
		SessionToken: sToken.SessionToken,
		Expiration:   &sToken.Expiration,
		MFASerial:    sToken.MFASerial,
	}
	if err := u.profile.StoreSessionToken(u.selectProfile, cre); err != nil {
		return errguide.Wrap(err,
			"Run actool again and retry the session-token action.",
			"If the long-lived credentials are invalid, replace them with aws-vault add <profile> first.",
		)
	}
	u.nextMode = model.SelectModeEnd
	return nil
}
