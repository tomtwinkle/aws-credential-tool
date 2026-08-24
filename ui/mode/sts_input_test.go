package mode

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestValidateMFAToken(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantError string
		wantGuide string
	}{
		{name: "valid six digit token", input: "123456"},
		{name: "non numeric token", input: "12a456", wantError: "Invalid number", wantGuide: "six-digit numeric"},
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
