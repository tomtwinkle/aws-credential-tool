package sts

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
		wantGuide     string
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
			wantGuide: "Add `region = <region>`",
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
				assert.ErrorContains(t, err, tc.wantGuide)
				return
			}

			assert.NilError(t, err)
			assert.Equal(t, client.Options().Region, tc.wantRegion)
		})
	}
}

func TestServiceRequestsProvideActionableFailures(t *testing.T) {
	cases := []struct {
		name          string
		operation     string
		response      string
		status        int
		wantAccessKey string
		wantSecretKey string
		wantSession   string
		wantAccount   string
		wantUserName  string
		wantError     string
		wantGuide     string
	}{
		{
			name:         "caller identity success",
			operation:    "GetCallerIdentity",
			response:     `<?xml version="1.0"?><GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/example-user</Arn><UserId>EXAMPLEUSER</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`,
			wantAccount:  "123456789012",
			wantUserName: "example-user",
		},
		{
			name:          "session token success",
			operation:     "GetSessionToken",
			response:      `<?xml version="1.0"?><GetSessionTokenResponse><GetSessionTokenResult><Credentials><SessionToken>EXAMPLESESSIONTOKEN</SessionToken><SecretAccessKey>EXAMPLESESSIONSECRET</SecretAccessKey><Expiration>2030-01-02T03:04:05Z</Expiration><AccessKeyId>EXAMPLESESSIONACCESS</AccessKeyId></Credentials></GetSessionTokenResult></GetSessionTokenResponse>`,
			wantAccessKey: "EXAMPLESESSIONACCESS",
			wantSecretKey: "EXAMPLESESSIONSECRET",
			wantSession:   "EXAMPLESESSIONTOKEN",
		},
		{
			name:      "STS failure explains recovery",
			operation: "GetCallerIdentity",
			status:    http.StatusInternalServerError,
			response:  "example STS failure",
			wantError: "sts fail",
			wantGuide: "Verify the AWS region",
		},
		{
			name:      "session token failure explains recovery",
			operation: "GetSessionToken",
			status:    http.StatusInternalServerError,
			response:  "example STS failure",
			wantError: "sts fail",
			wantGuide: "Verify the AWS region",
		},
		{
			name:      "empty session credentials explains recovery",
			operation: "GetSessionToken",
			response:  `<?xml version="1.0"?><GetSessionTokenResponse><GetSessionTokenResult></GetSessionTokenResult></GetSessionTokenResponse>`,
			wantError: "sts credentials are empty",
			wantGuide: "valid long-lived credentials",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, readErr := io.ReadAll(r.Body)
				if readErr != nil {
					http.Error(w, readErr.Error(), http.StatusBadRequest)
					return
				}
				if !strings.Contains(string(body), "Action="+tc.operation) {
					http.Error(w, "unexpected STS operation", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "text/xml")
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = io.WriteString(w, tc.response)
			}))
			defer server.Close()

			t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)
			t.Setenv("AWS_REGION", "us-west-2")
			t.Setenv("AWS_DEFAULT_REGION", "")
			t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "config"))
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials"))
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

			service := NewService("EXAMPLEACCESSKEY", "EXAMPLESECRETKEY", "us-west-2")
			if tc.operation == "GetCallerIdentity" {
				account, err := service.Account()
				if tc.wantError != "" {
					assert.ErrorContains(t, err, tc.wantError)
					assert.ErrorContains(t, err, tc.wantGuide)
					return
				}
				assert.NilError(t, err)
				assert.Equal(t, account.Account, tc.wantAccount)
				assert.Equal(t, account.UserName, tc.wantUserName)
				return
			}

			token, err := service.SessionToken(43200, "123456789012", "example-user", "123456")
			if tc.wantError != "" {
				assert.ErrorContains(t, err, tc.wantError)
				assert.ErrorContains(t, err, tc.wantGuide)
				return
			}
			assert.NilError(t, err)
			assert.Equal(t, token.AccessKey, tc.wantAccessKey)
			assert.Equal(t, token.SecretKey, tc.wantSecretKey)
			assert.Equal(t, token.SessionToken, tc.wantSession)
		})
	}
}

func TestMFASerialFromCallerARN(t *testing.T) {
	cases := []struct {
		name         string
		callerARN    string
		account      string
		wantSerial   string
		wantUserName string
	}{
		{
			name:         "standard IAM user",
			callerARN:    "arn:aws:iam::123456789012:user/example-user",
			account:      "123456789012",
			wantSerial:   "arn:aws:iam::123456789012:mfa/example-user",
			wantUserName: "example-user",
		},
		{
			name:         "government IAM user",
			callerARN:    "arn:aws-us-gov:iam::123456789012:user/example-user",
			account:      "123456789012",
			wantSerial:   "arn:aws-us-gov:iam::123456789012:mfa/example-user",
			wantUserName: "example-user",
		},
		{
			name:         "assumed role has no user MFA serial",
			callerARN:    "arn:aws:sts::123456789012:assumed-role/example-role/example-session",
			account:      "123456789012",
			wantUserName: "example-session",
		},
		{
			name:         "malformed caller ARN keeps a display name",
			callerARN:    "example-session",
			wantUserName: "example-session",
		},
		{
			name:         "IAM user without an account cannot derive a serial",
			callerARN:    "arn:aws:iam:::user/example-user",
			wantUserName: "example-user",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serial, userName := mfaSerialFromCallerARN(tc.callerARN, tc.account)
			assert.Equal(t, serial, tc.wantSerial)
			assert.Equal(t, userName, tc.wantUserName)
		})
	}
}

func TestResolveMFASerialRequiresSource(t *testing.T) {
	service := &service{region: "us-west-2"}
	cases := []struct {
		name     string
		serial   string
		userName string
	}{
		{name: "missing account and user", serial: "", userName: ""},
		{name: "missing account", serial: "", userName: "example-user"},
		{name: "missing user", serial: "123456789012", userName: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := service.resolveMFASerial(tc.serial, tc.userName)
			assert.ErrorContains(t, err, "MFA serial number is not available")
			assert.ErrorContains(t, err, "mfa_serial")
		})
	}
}

func TestPartitionForRegion(t *testing.T) {
	cases := []struct {
		name   string
		region string
		want   string
	}{
		{name: "standard", region: "us-west-2", want: "aws"},
		{name: "china", region: "cn-north-1", want: "aws-cn"},
		{name: "government", region: "us-gov-west-1", want: "aws-us-gov"},
		{name: "secret", region: "us-iso-east-1", want: "aws-iso"},
		{name: "secret restricted", region: "us-isob-east-1", want: "aws-iso-b"},
		{name: "future secret east", region: "us-isof-east-1", want: "aws-iso-f"},
		{name: "future secret south", region: "us-isof-south-1", want: "aws-iso-f"},
		{name: "europe secret", region: "eu-isoe-west-1", want: "aws-iso-e"},
		{name: "europe sovereign", region: "eusc-de-east-1", want: "aws-eusc"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, partitionForRegion(tc.region), tc.want)
		})
	}
}

func TestServiceRequestsRequireRegion(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL_STS", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	service := NewService("EXAMPLEACCESSKEY", "EXAMPLESECRETKEY", "")
	_, accountErr := service.Account()
	assert.ErrorContains(t, accountErr, "AWS region is not configured")
	_, tokenErr := service.SessionToken(43200, "123456789012", "example-user", "123456")
	assert.ErrorContains(t, tokenErr, "AWS region is not configured")
}

func TestSessionTokenSendsCorrectMFASerial(t *testing.T) {
	cases := []struct {
		name             string
		region           string
		configuredSerial string
		wantSerial       string
	}{
		{
			name:       "standard partition from region",
			region:     "us-west-2",
			wantSerial: "arn:aws:iam::123456789012:mfa/example-user",
		},
		{
			name:       "china partition from region",
			region:     "cn-north-1",
			wantSerial: "arn:aws-cn:iam::123456789012:mfa/example-user",
		},
		{
			name:             "configured device ARN",
			region:           "us-gov-west-1",
			configuredSerial: "arn:aws-us-gov:iam::123456789012:mfa/example-device",
			wantSerial:       "arn:aws-us-gov:iam::123456789012:mfa/example-device",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, readErr := io.ReadAll(r.Body)
				assert.NilError(t, readErr)
				values, parseErr := url.ParseQuery(string(body))
				assert.NilError(t, parseErr)
				assert.Equal(t, values.Get("Action"), "GetSessionToken")
				assert.Equal(t, values.Get("SerialNumber"), tc.wantSerial)
				w.Header().Set("Content-Type", "text/xml")
				_, _ = io.WriteString(w, `<?xml version="1.0"?><GetSessionTokenResponse><GetSessionTokenResult><Credentials><SessionToken>EXAMPLESESSIONTOKEN</SessionToken><SecretAccessKey>EXAMPLESESSIONSECRET</SecretAccessKey><Expiration>2030-01-02T03:04:05Z</Expiration><AccessKeyId>EXAMPLESESSIONACCESS</AccessKeyId></Credentials></GetSessionTokenResult></GetSessionTokenResponse>`)
			}))
			defer server.Close()

			t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)
			t.Setenv("AWS_REGION", tc.region)
			t.Setenv("AWS_DEFAULT_REGION", "")
			t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "config"))
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials"))
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

			service := NewServiceWithMFASerial("EXAMPLEACCESSKEY", "EXAMPLESECRETKEY", tc.region, tc.configuredSerial)
			_, err := service.SessionToken(43200, "123456789012", "example-user", "123456")
			assert.NilError(t, err)
		})
	}
}
