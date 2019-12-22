package ui

import (
	"aws-credential-tool/io/profile"
	"aws-credential-tool/ui/mode"
	"aws-credential-tool/ui/model"
	tui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/pkg/errors"
)

type UI interface {
	Run() error
}

type ui struct {
	msgWindow *widgets.Paragraph
	list      *widgets.List

	p   profile.Profile
	mps mode.ProfileSelect

	mode     model.SelectMode
	nextMode model.SelectMode
	mProfile *profile.Model
}

func NewUI() (UI, error) {
	initMode := model.SelectModeProfileSelect
	msgWindow := widgets.NewParagraph()
	list := widgets.NewList()
	p := profile.NewProfile()

	mProfile, err := p.Load()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if mProfile == nil {
		return nil, errors.New("Profile not defined.")
	}
	mps := mode.NewModeProfileSelect(mProfile)

	return &ui{msgWindow: msgWindow, list: list, p: p, mps: mps, nextMode: initMode, mProfile: mProfile}, nil
}

func (u *ui) Run() error {
	// initialize termui
	if err := tui.Init(); err != nil {
		return errors.WithStack(err)
	}
	defer tui.Close()

	// initial render
	if err := u.render(); err != nil {
		return errors.WithStack(err)
	}

	// ui control loop
	if err := u.controlLoop(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (u *ui) render() error {
	uiModel, err := u.renderData()
	if err != nil {
		return errors.WithStack(err)
	}
	if uiModel == nil {
		return nil
	}

	// message
	u.msgWindow.Text = uiModel.Message
	u.msgWindow.SetRect(0, 0, 40, 4)

	// render list
	u.list.Title = uiModel.ListTitle
	u.list.Rows = uiModel.ListData
	u.list.TextStyle = tui.NewStyle(tui.ColorYellow)
	u.list.WrapText = false
	u.list.SetRect(0, 4, 40, 10)

	return nil
}

func (u *ui) renderData() (*model.Model, error) {
	var uiModel *model.Model
	var err error
	switch u.nextMode {
	case model.SelectModeProfileSelect:
		uiModel, err = u.mps.RenderData()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		uiModel.Message = " Select use credential.\n  q:quit, Enter:use credential, s:sts mode"
		u.mode = model.SelectModeProfileSelect
		u.nextMode = model.SelectModeEnd
	case model.SelectModeSTS:
		u.mode = model.SelectModeSTS
	case model.SelectModeEnd:
		credential := u.mProfile.Credentials[u.list.SelectedRow]
		if err := u.p.SetDefault(u.mProfile, credential.Name); err != nil {
			return nil, errors.WithStack(err)
		}
		u.mode = model.SelectModeEnd
	default:
		return nil, errors.New("Undefined mode.")
	}

	return uiModel, nil
}

func (u *ui) controlLoop() error {
	previousKey := ""
	uiEvents := tui.PollEvents()
	for {
		if u.mode == model.SelectModeEnd {
			return nil
		}

		e := <-uiEvents
		switch e.ID {
		case "q", "<C-c>":
			return nil
		case "j", "<Down>":
			u.list.ScrollDown()
		case "k", "<Up>":
			u.list.ScrollUp()
		case "<C-d>":
			u.list.ScrollHalfPageDown()
		case "<C-u>":
			u.list.ScrollHalfPageUp()
		case "<C-f>":
			u.list.ScrollPageDown()
		case "<C-b>":
			u.list.ScrollPageUp()
		case "g":
			if previousKey == "g" {
				u.list.ScrollTop()
			}
		case "<Home>":
			u.list.ScrollTop()
		case "G", "<End>":
			u.list.ScrollBottom()
		case "<Enter>":
			if err := u.render(); err != nil {
				return errors.WithStack(err)
			}
		}

		if previousKey == "g" {
			previousKey = ""
		} else {
			previousKey = e.ID
		}

		tui.Render(u.msgWindow)
		tui.Render(u.list)
	}
}
