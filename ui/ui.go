package ui

import (
	"github.com/pkg/errors"
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
		return nil, errors.WithStack(err)
	}

	mProfile, err := p.Load()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if mProfile == nil || len(mProfile.Credentials) == 0 {
		return nil, errors.New("Profile not defined.")
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
			return errors.WithStack(err)
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
			return false, errors.WithStack(err)
		}
	case model.SelectModeActionSelect:
		if err := u.modeActionSelect(); err != nil {
			return false, errors.WithStack(err)
		}
	case model.SelectModeSTS:
		if err := u.modeSTS(); err != nil {
			return false, errors.WithStack(err)
		}
	case model.SelectModeEnd:
		u.mode = model.SelectModeEnd
		if err := u.profile.SetSelected(u.selectProfile); err != nil {
			return false, errors.WithStack(err)
		}
		return true, nil
	default:
		return false, errors.New("Undefined mode.")
	}
	return false, nil
}

func (u *ui) modeProfileSelect() error {
	u.mode = model.SelectModeProfileSelect
	profileStr, err := u.profileSelect.Select()
	if err != nil {
		return errors.WithStack(err)
	}
	if profileStr == "" {
		return errors.New("not select profile.")
	}
	cre, err := u.profile.Credential(profileStr)
	if err != nil {
		return errors.WithStack(err)
	}
	conf, err := u.profile.Config(u.mProfile, profileStr)
	if err != nil {
		return errors.WithStack(err)
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
		return errors.WithStack(err)
	}
	u.nextMode = nextMode
	return nil
}

func (u *ui) modeSTS() error {
	u.mode = model.SelectModeSTS
	sts := mode.NewModeSTS(u.selectCredential.AccessKey, u.selectCredential.SecretKey, u.selectConfig.Region)
	sToken, err := sts.GetSessionToken()
	if err != nil {
		return errors.WithStack(err)
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
		return errors.WithStack(err)
	}
	u.nextMode = model.SelectModeEnd
	return nil
}
