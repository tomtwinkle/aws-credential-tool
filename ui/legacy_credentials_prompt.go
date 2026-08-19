package ui

import (
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/pkg/errors"
)

type legacyCredentialCleanupOption struct {
	Name   string
	Detail string
	Delete bool
}

func promptDeleteLegacyCredentials(path string) (bool, error) {
	options := []legacyCredentialCleanupOption{
		{
			Name:   "Delete file now.",
			Detail: fmt.Sprintf("Remove %s after importing it into secure storage.", path),
			Delete: true,
		},
		{
			Name: "Keep backup for manual deletion.",
			Detail: fmt.Sprintf("Move %s to %s.actool-backup so AWS CLI cannot read the plaintext source. "+
				"Delete the backup manually later.", path, path),
			Delete: false,
		},
	}

	prompt := promptui.Select{
		Label: "Legacy credentials file detected. Delete it now?",
		Items: options,
		Templates: &promptui.SelectTemplates{
			Label:    "{{ . }}",
			Active:   "-> {{ .Name | cyan }}",
			Inactive: "   {{ .Name | cyan }}",
			Selected: "{{ .Name | green }}",
			Details: `
--------- Option ----------
{{ .Detail }}
`,
		},
	}

	idx, _, err := prompt.Run()
	if err != nil {
		return false, errors.WithStack(err)
	}

	return options[idx].Delete, nil
}
