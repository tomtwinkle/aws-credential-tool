package mode

import (
	"fmt"
	"github.com/chzyer/readline"
	"github.com/manifoldco/promptui"
	"github.com/pkg/errors"
	"github.com/tomtwinkle/aws-credential-tool/ui/model"
)

type mode struct {
	Name       string
	SelectMode model.SelectMode
	Detail     string
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
			Detail:     "Set selected profile as default credentials",
			SelectMode: model.SelectModeEnd,
		},
		{
			Name:       "Set choose sessionToken.",
			Detail:     "Obtain sessionToken credentials using AWS STS and set as default credentials",
			SelectMode: model.SelectModeSTS,
		},
	}

	templates := &promptui.SelectTemplates{
		Label:    "{{ . }}?",
		Active:   "-> {{ .Name | cyan }}",
		Inactive: "  {{ .Name | cyan }}",
		Selected: "-> {{ .Name | green | cyan }}",
		Details: `
--------- Action Detail ----------
{{ .Detail }}
`,
	}

	prompt := promptui.Select{
		Keys: &promptui.SelectKeys{
			Next: promptui.Key{Code: readline.CharNext, Display: "↓"},
			Prev: promptui.Key{Code: readline.CharPrev, Display: "↑"},
		},
		Label:     "Select Action",
		Items:     modes,
		Templates: templates,
	}

	idx, _, err := prompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return 0, errors.WithStack(err)
	}

	return modes[idx].SelectMode, nil
}
