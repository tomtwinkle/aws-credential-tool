package errguide

import (
	"errors"
	"testing"

	"gotest.tools/v3/assert"
)

var testBackendUnavailable = errors.New("backend unavailable")

func TestActionableErrorFormatting(t *testing.T) {
	cases := []struct {
		name      string
		makeError func() error
		wantText  string
		wantCause error
	}{
		{
			name: "new error includes numbered steps",
			makeError: func() error {
				return New("profile is missing", "Run actool.", "Add a profile first.")
			},
			wantText: "How to fix:\n1. Run actool.\n2. Add a profile first.",
		},
		{
			name: "wrapped error preserves cause",
			makeError: func() error {
				return Wrap(testBackendUnavailable, "Unlock the keyring.")
			},
			wantText:  "How to fix:\n1. Unlock the keyring.",
			wantCause: testBackendUnavailable,
		},
		{
			name: "existing guide is not duplicated",
			makeError: func() error {
				return Wrap(New("region is missing", "Set AWS_REGION."), "Run actool again.")
			},
			wantText: "How to fix:\n1. Set AWS_REGION.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.makeError()
			assert.ErrorContains(t, err, tc.wantText)
			if tc.wantCause != nil {
				assert.ErrorIs(t, err, tc.wantCause)
			}
		})
	}
}
