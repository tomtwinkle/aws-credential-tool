package sts

import (
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func TestServiceClientRegionResolution(t *testing.T) {
	cases := []struct {
		name          string
		profileRegion string
		awsRegion     string
		defaultRegion string
		configRegion  string
		wantRegion    string
		wantError     string
	}{
		{
			name:          "AWS_REGION overrides profile region",
			profileRegion: "eu-west-1",
			awsRegion:     "us-west-2",
			wantRegion:    "us-west-2",
		},
		{
			name:          "AWS_DEFAULT_REGION is an aws-vault compatible fallback",
			defaultRegion: "us-east-2",
			wantRegion:    "us-east-2",
		},
		{
			name:          "selected profile region",
			profileRegion: "ap-northeast-1",
			wantRegion:    "ap-northeast-1",
		},
		{
			name:         "shared default config",
			configRegion: "ca-central-1",
			wantRegion:   "ca-central-1",
		},
		{
			name:      "missing region",
			wantError: "AWS region is not configured",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config")
			credentialsPath := filepath.Join(t.TempDir(), "credentials")
			if tc.configRegion != "" {
				assert.NilError(t, os.WriteFile(configPath, []byte("[default]\nregion = "+tc.configRegion+"\n"), 0o600))
			} else {
				assert.NilError(t, os.WriteFile(configPath, nil, 0o600))
			}
			assert.NilError(t, os.WriteFile(credentialsPath, nil, 0o600))

			t.Setenv("AWS_CONFIG_FILE", configPath)
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsPath)
			t.Setenv("AWS_PROFILE", "")
			t.Setenv("AWS_REGION", tc.awsRegion)
			t.Setenv("AWS_DEFAULT_REGION", tc.defaultRegion)
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

			client, err := (&service{
				accessKey: "EXAMPLEACCESSKEY",
				secretKey: "EXAMPLESECRETKEY",
				region:    tc.profileRegion,
			}).client()
			if tc.wantError != "" {
				assert.ErrorContains(t, err, tc.wantError)
				return
			}

			assert.NilError(t, err)
			assert.Equal(t, client.Options().Region, tc.wantRegion)
		})
	}
}
