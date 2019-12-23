package mode

import (
	"aws-credential-tool/io/sts"
	"fmt"
	"github.com/manifoldco/promptui"
	"github.com/pkg/errors"
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
	serialNumber, err := s.inputSerialNumber()
	if err == nil {
		return nil, errors.WithStack(err)
	}

	user, err := s.inputUser()
	if err == nil {
		return nil, errors.WithStack(err)
	}

	token, err := s.inputToken()
	if err == nil {
		return nil, errors.WithStack(err)
	}

	sToken, err := s.sts.SessionToken(900, serialNumber, user, token)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return sToken, nil
}

func (s *stsInput) inputSerialNumber() (string, error) {
	validate := func(input string) error {
		_, err := strconv.ParseFloat(input, 64)
		if err != nil {
			return errors.New("Invalid number")
		}
		if len(input) != 12 {
			return errors.New("Invalid AWS Account SerialNumber.")
		}
		return nil
	}

	prompt := promptui.Prompt{
		Label:    "AWS Account SerialNumber",
		Validate: validate,
	}

	result, err := prompt.Run()

	if err != nil {
		fmt.Printf("%v\n", err.Error())
		return "", err
	}
	return result, nil
}

func (s *stsInput) inputUser() (string, error) {
	validate := func(input string) error {
		if len(input) == 0 {
			return errors.New("Account user name is not entered.")
		}
		return nil
	}

	prompt := promptui.Prompt{
		Label:    "AWS Account UserName",
		Validate: validate,
	}

	result, err := prompt.Run()

	if err != nil {
		fmt.Printf("%v\n", err.Error())
		return "", err
	}
	return result, nil
}

func (s *stsInput) inputToken() (string, error) {
	validate := func(input string) error {
		_, err := strconv.ParseFloat(input, 64)
		if err != nil {
			return errors.New("Invalid number")
		}
		if len(input) != 6 {
			return errors.New("Invalid Token.")
		}
		return nil
	}

	prompt := promptui.Prompt{
		Label:    "MFA Token",
		Validate: validate,
	}

	result, err := prompt.Run()

	if err != nil {
		fmt.Printf("%v\n", err.Error())
		return "", err
	}
	return result, nil
}
