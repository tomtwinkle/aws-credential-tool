package mode

import (
	"errors"
	"testing"

	"github.com/tomtwinkle/aws-credential-tool/io/sts"
	"gotest.tools/v3/assert"
)

type fakeSTSService struct {
	account      *sts.Account
	accountErr   error
	token        *sts.SessionToken
	tokenErr     error
	serialNumber string
	userName     string
	tokenCode    string
}

func (f *fakeSTSService) Account() (*sts.Account, error) {
	return f.account, f.accountErr
}

func (f *fakeSTSService) SessionToken(_ int64, serialNumber string, userName string, token string) (*sts.SessionToken, error) {
	f.serialNumber = serialNumber
	f.userName = userName
	f.tokenCode = token
	return f.token, f.tokenErr
}

func TestSTSInputGetSessionToken(t *testing.T) {
	cases := []struct {
		name             string
		accountErr       error
		promptErr        error
		tokenErr         error
		wantErr          string
		wantSerial       string
		wantUserName     string
		wantToken        string
		wantSessionToken string
	}{
		{name: "caller identity failure", accountErr: errors.New("identity failed"), wantErr: "identity failed"},
		{name: "MFA prompt failure", promptErr: errors.New("prompt failed"), wantErr: "prompt failed"},
		{name: "session token failure", tokenErr: errors.New("token failed"), wantErr: "token failed", wantSerial: "arn:aws:iam::123456789012:mfa/example-device", wantUserName: "example-user", wantToken: "123456"},
		{name: "success", wantSerial: "arn:aws:iam::123456789012:mfa/example-device", wantUserName: "example-user", wantToken: "123456", wantSessionToken: "EXAMPLESESSIONTOKEN"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSTSService{
				account: &sts.Account{
					Account:   "123456789012",
					UserName:  "example-user",
					MFASerial: "arn:aws:iam::123456789012:mfa/example-device",
				},
				accountErr: tc.accountErr,
				tokenErr:   tc.tokenErr,
				token:      &sts.SessionToken{SessionToken: tc.wantSessionToken},
			}
			input := &stsInput{
				sts: fake,
				promptToken: func(string, string) (string, error) {
					return "123456", tc.promptErr
				},
			}

			got, err := input.GetSessionToken()
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			assert.NilError(t, err)
			assert.Equal(t, got.SessionToken, tc.wantSessionToken)
			assert.Equal(t, fake.serialNumber, tc.wantSerial)
			assert.Equal(t, fake.userName, tc.wantUserName)
			assert.Equal(t, fake.tokenCode, tc.wantToken)
		})
	}
}

func TestValidateMFAToken(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantError string
		wantGuide string
	}{
		{name: "valid six digit token", input: "123456"},
		{name: "non numeric token", input: "12a456", wantError: "Invalid number", wantGuide: "six-digit numeric"},
		{name: "decimal token", input: "123.45", wantError: "Invalid number", wantGuide: "six-digit numeric"},
		{name: "exponent token", input: "1.2e+3", wantError: "Invalid number", wantGuide: "six-digit numeric"},
		{name: "signed token", input: "+12345", wantError: "Invalid number", wantGuide: "six-digit numeric"},
		{name: "short token", input: "12345", wantError: "Invalid Token.", wantGuide: "six-digit numeric"},
		{name: "long token", input: "1234567", wantError: "Invalid Token.", wantGuide: "Retry before the token expires."},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMFAToken(tc.input)
			if tc.wantError == "" {
				assert.NilError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.wantError)
			assert.ErrorContains(t, err, tc.wantGuide)
		})
	}
}
