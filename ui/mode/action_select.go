package mode

import (
	"aws-credential-tool/ui/model"
	"fmt"
	"github.com/chzyer/readline"
	"github.com/manifoldco/promptui"
	"github.com/pkg/errors"
)

type mode struct {
	Name       string
	SelectMode model.SelectMode
}

type ActionSelect interface {
	Select() (model.SelectMode, error)
}

type actionSelect struct {
}

func NewModeActionSelect() ActionSelect {
	return &actionSelect{}
}

func (a *actionSelect) Select() (model.SelectMode, error) {
	modes := []mode{
		{
			Name:       "Set choose profile.",
			SelectMode: model.SelectModeEnd,
		},
		{
			Name:       "Set choose profile STS SessionToken.",
			SelectMode: model.SelectModeSTS,
		},
	}

	prompt := promptui.Select{
		Keys: &promptui.SelectKeys{
			Next: promptui.Key{Code: readline.CharNext, Display: "↓"},
			Prev: promptui.Key{Code: readline.CharPrev, Display: "↑"},
		},
		Label: "Select Action",
		Items: modes,
	}

	idx, _, err := prompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return 0, errors.WithStack(err)
	}

	return modes[idx].SelectMode, nil
}
