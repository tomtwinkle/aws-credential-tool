package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/tomtwinkle/aws-credential-tool/io/profile"
)

func configureIsolatedRuntime(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, ".aws", "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, ".aws", "credentials"))
	t.Setenv("AWS_VAULT_BACKEND", "file")
	t.Setenv("AWS_VAULT_FILE_DIR", filepath.Join(home, "aws-vault"))
	t.Setenv("AWS_VAULT_FILE_PASSPHRASE", "test-passphrase")
}

func writeRuntimeLegacyCredentials(t *testing.T) {
	t.Helper()
	path := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	assert.NilError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	assert.NilError(t, os.WriteFile(path, []byte(`[default]
aws_access_key_id = DEFAULTACCESSKEY
aws_secret_access_key = DEFAULTSECRETKEY

[dev]
aws_access_key_id = DEVACCESSKEY
aws_secret_access_key = DEVSECRETKEY
`), 0o600))
}

func initializeRuntimeProfile(t *testing.T) {
	t.Helper()
	p, err := profile.NewProfile()
	assert.NilError(t, err)
	_, err = p.Load()
	assert.NilError(t, err)
}

func captureStdout(t *testing.T, fn func() error) ([]byte, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	assert.NilError(t, err)
	originalStdout := os.Stdout
	os.Stdout = writer
	runErr := fn()
	closeErr := writer.Close()
	os.Stdout = originalStdout
	assert.NilError(t, closeErr)
	output, readErr := io.ReadAll(reader)
	assert.NilError(t, readErr)
	assert.NilError(t, reader.Close())
	return output, runErr
}

func TestRunVersionFlags(t *testing.T) {
	for _, flag := range []string{"-v", "--version"} {
		t.Run(flag, func(t *testing.T) {
			output, runErr := captureStdout(t, func() error {
				return run([]string{flag})
			})
			assert.NilError(t, runErr)
			assert.Assert(t, strings.Contains(string(output), "aws-credential-tool version"))
		})
	}
}

func TestRunWithoutArgumentsReturnsUIInitializationError(t *testing.T) {
	configureIsolatedRuntime(t)

	assert.ErrorContains(t, run(nil), "Profile not defined.")
}

func TestRunArgumentValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "unknown command", args: []string{"unknown"}, want: "unknown command: unknown"},
		{name: "unknown flag", args: []string{"--unknown"}, want: "flag provided but not defined"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorContains(t, run(tc.args), tc.want)
		})
	}
}

func TestRunCredentialProcessArgumentValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "unexpected positional argument", args: []string{"--profile", "dev", "extra"}, want: "unexpected arguments"},
		{name: "unknown flag", args: []string{"--unknown"}, want: "flag provided but not defined"},
		{name: "missing flag value", args: []string{"--profile"}, want: "flag needs an argument"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorContains(t, runCredentialProcess(tc.args), tc.want)
		})
	}
}

func TestRunCredentialProcessSuccess(t *testing.T) {
	cases := []struct {
		name          string
		args          []string
		wantAccessKey string
	}{
		{name: "selected profile", wantAccessKey: "DEFAULTACCESSKEY"},
		{name: "explicit profile", args: []string{"--profile", "dev"}, wantAccessKey: "DEVACCESSKEY"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configureIsolatedRuntime(t)
			writeRuntimeLegacyCredentials(t)
			initializeRuntimeProfile(t)

			output, err := captureStdout(t, func() error {
				return runCredentialProcess(tc.args)
			})
			assert.NilError(t, err)

			var payload map[string]interface{}
			assert.NilError(t, json.Unmarshal(output, &payload))
			assert.Equal(t, payload["Version"], float64(1))
			assert.Equal(t, payload["AccessKeyId"], tc.wantAccessKey)
			assert.Assert(t, payload["SecretAccessKey"] != nil)
		})
	}
}

func TestRunCredentialProcessErrors(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(*testing.T)
		args    []string
		wantErr string
	}{
		{
			name:    "profile is not initialized",
			setup:   func(t *testing.T) { configureIsolatedRuntime(t) },
			wantErr: "not initialized",
		},
		{
			name: "profile backend cannot be opened",
			setup: func(t *testing.T) {
				configureIsolatedRuntime(t)
				t.Setenv("AWS_VAULT_BACKEND", "invalid-backend")
			},
			wantErr: "backend",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)
			assert.ErrorContains(t, runCredentialProcess(tc.args), tc.wantErr)
		})
	}
}

func TestRunCredentialProcessReturnsStdoutWriteError(t *testing.T) {
	configureIsolatedRuntime(t)
	writeRuntimeLegacyCredentials(t)
	initializeRuntimeProfile(t)

	path := filepath.Join(t.TempDir(), "stdout")
	assert.NilError(t, os.WriteFile(path, nil, 0o600))
	readOnlyStdout, err := os.Open(path)
	assert.NilError(t, err)
	originalStdout := os.Stdout
	os.Stdout = readOnlyStdout
	runErr := runCredentialProcess([]string{"--profile", "dev"})
	os.Stdout = originalStdout
	assert.NilError(t, readOnlyStdout.Close())
	assert.Assert(t, runErr != nil)
}
