package mode

import (
	"aws-credential-tool/io/profile"
	"aws-credential-tool/ui/model"
	"fmt"
)

type ProfileSelect interface {
	RenderData() (*model.Model, error)
}

type profileSelect struct {
	mProfile *profile.Model
}

func NewModeProfileSelect(mProfile *profile.Model) ProfileSelect {
	return &profileSelect{mProfile: mProfile}
}

func (l *profileSelect) RenderData() (*model.Model, error) {
	var uiModel = new(model.Model)
	// render list
	uiModel.ListTitle = "Credentials"
	uiModel.ListData = make([]string, len(l.mProfile.Credentials))
	for idx, credectial := range l.mProfile.Credentials {
		uiModel.ListData[idx] = fmt.Sprintf("[%d] %s", idx, credectial.Name)
	}
	return uiModel, nil
}
