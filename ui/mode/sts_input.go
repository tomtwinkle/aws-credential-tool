package mode

import (
	"errors"
	"fmt"
	"github.com/manifoldco/promptui"
	"github.com/tomtwinkle/aws-credential-tool/io/sts"
	"strconv"
)

type STSInput interface {
	GetSessionToken() (*sts.SessionToken, error)
}

type stsInput struct {
	sts sts.Service
}

func NewModeSTS(accessKey string, secretKey string, region string) STSInput {
	s := sts.NewService(accessKey, secretKey, region)
	return &stsInput{sts: s}
}

func (s *stsInput) GetSessionToken() (*sts.SessionToken, error) {
	account, err := s.sts.Account()
	if err != nil {
		return nil, err
	}

	token, err := s.inputToken(account.Account, account.UserName)
	if err != nil {
		return nil, err
	}

	sToken, err := s.sts.SessionToken(43200, account.Account, account.UserName, token)
	if err != nil {
		return nil, err
	}

	fmt.Println("Success get session token.")

	return sToken, nil
}

func (s *stsInput) inputToken(account string, userName string) (string, error) {
	validate := func(input string) error {
		_, err := strconv.ParseFloat(input, 64)
		if err != nil {
			return errors.New("Invalid number") //nolint:staticcheck // preserve the existing user-facing prompt text
		}
		if len(input) != 6 {
			return errors.New("Invalid Token.") //nolint:staticcheck // preserve the existing user-facing prompt text
		}
		return nil
	}

	prompt := promptui.Prompt{
		Label:    fmt.Sprintf("Input MFA Token. Account[%s] User[%s]", account, userName),
		Validate: validate,
	}

	result, err := prompt.Run()

	if err != nil {
		fmt.Printf("%v\n", err.Error())
		return "", err
	}
	return result, nil
}
