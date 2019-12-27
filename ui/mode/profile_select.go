package mode

import (
	"fmt"
	"github.com/chzyer/readline"
	"github.com/manifoldco/promptui"
	"github.com/pkg/errors"
	"github.com/tomtwinkle/aws-credential-tool/io/profile"
)

type ProfileSelect interface {
	Select() (string, error)
}

type profileSelect struct {
	mProfile *profile.Model
}

func NewModeProfileSelect(mProfile *profile.Model) ProfileSelect {
	return &profileSelect{mProfile: mProfile}
}

func (l *profileSelect) Select() (string, error) {
	var profiles = make([]string, len(l.mProfile.Credentials))
	for i, p := range l.mProfile.Credentials {
		profiles[i] = p.Name
	}

	templates := &promptui.SelectTemplates{
		Label:    "{{ . }}?",
		Active:   "-> {{ . | cyan }}",
		Inactive: "  {{ . | cyan }}",
		Selected: "-> {{ . | green | cyan }}",
	}

	prompt := promptui.Select{
		Keys: &promptui.SelectKeys{
			Next: promptui.Key{Code: readline.CharNext, Display: "↓"},
			Prev: promptui.Key{Code: readline.CharPrev, Display: "↑"},
		},
		Label:     "Select Profile",
		Items:     profiles,
		Templates: templates,
	}

	_, result, err := prompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return "", errors.WithStack(err)
	}

	fmt.Printf("choose profile [%q]\n", result)
	return result, nil
}
