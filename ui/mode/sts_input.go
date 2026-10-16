package mode

import (
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/tomtwinkle/aws-credential-tool/internal/errguide"
	"github.com/tomtwinkle/aws-credential-tool/io/sts"
)

type STSInput interface {
	GetSessionToken() (*sts.SessionToken, error)
}

type stsInput struct {
	sts         sts.Service
	promptToken func(account string, userName string) (string, error)
}

func NewModeSTS(accessKey string, secretKey string, region string) STSInput {
	return NewModeSTSWithMFASerial(accessKey, secretKey, region, "")
}

func NewModeSTSWithMFASerial(accessKey string, secretKey string, region string, mfaSerial string) STSInput {
	s := sts.NewServiceWithMFASerial(accessKey, secretKey, region, mfaSerial)
	input := &stsInput{sts: s}
	input.promptToken = input.inputToken
	return input
}

func (s *stsInput) GetSessionToken() (*sts.SessionToken, error) {
	account, err := s.sts.Account()
	if err != nil {
		return nil, err
	}

	promptToken := s.promptToken
	if promptToken == nil {
		promptToken = s.inputToken
	}
	token, err := promptToken(account.Account, account.UserName)
	if err != nil {
		return nil, err
	}

	sToken, err := s.sts.SessionToken(43200, account.MFASerial, account.UserName, token)
	if err != nil {
		return nil, err
	}

	fmt.Println("Success get session token.")

	return sToken, nil
}

func (s *stsInput) inputToken(account string, userName string) (string, error) {
	prompt := promptui.Prompt{
		Label:    fmt.Sprintf("Input MFA Token. Account[%s] User[%s]", account, userName),
		Validate: validateMFAToken,
	}

	result, err := prompt.Run()

	if err != nil {
		fmt.Printf("%v\n", err.Error())
		return "", err
	}
	return result, nil
}

func validateMFAToken(input string) error {
	if len(input) != 6 {
		return errguide.New("Invalid Token.",
			"Enter the current six-digit numeric MFA token.",
			"Retry before the token expires.",
		) //nolint:staticcheck // preserve the existing user-facing prompt text
	}
	for i := 0; i < len(input); i++ {
		if input[i] < '0' || input[i] > '9' {
			return errguide.New("Invalid number",
				"Enter the current six-digit numeric MFA token.",
				"Retry before the token expires.",
			) //nolint:staticcheck // preserve the existing user-facing prompt text
		}
	}
	return nil
}
