//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"gopkg.in/ini.v1"
	"gotest.tools/v3/assert"
)

type acceptanceRuntime struct {
	home            string
	configPath      string
	credentialsPath string
	storePath       string
	binaryPath      string
	env             []string
}

type acceptancePromptStep struct {
	marker string
	input  string
}

func newAcceptanceRuntime(t *testing.T, stsEndpoint string) *acceptanceRuntime {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configDir := filepath.Join(home, ".aws")
	configPath := filepath.Join(configDir, "config")
	credentialsPath := filepath.Join(configDir, "credentials")
	storePath := filepath.Join(home, ".awsvault", "keys")
	assert.NilError(t, os.MkdirAll(configDir, 0o700))

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"AWS_CONFIG_FILE=" + configPath,
		"AWS_SHARED_CREDENTIALS_FILE=" + credentialsPath,
		"AWS_VAULT_BACKEND=file",
		"AWS_VAULT_FILE_DIR=" + storePath,
		"AWS_VAULT_FILE_PASSPHRASE=example-passphrase",
		"AWS_REGION=",
		"AWS_DEFAULT_REGION=",
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_PAGER=",
		"TERM=xterm",
	}
	if stsEndpoint != "" {
		env = append(env, "AWS_ENDPOINT_URL_STS="+stsEndpoint)
	}

	return &acceptanceRuntime{
		home:            home,
		configPath:      configPath,
		credentialsPath: credentialsPath,
		storePath:       storePath,
		binaryPath:      filepath.Join(root, "actool"),
		env:             env,
	}
}

func writeAcceptanceFixture(t *testing.T, rt *acceptanceRuntime) {
	t.Helper()
	assert.NilError(t, os.WriteFile(rt.configPath, []byte(`[default]
region = us-west-2
output = json

[profile example-develop]

[profile example-stage]
`), 0o600))
	assert.NilError(t, os.WriteFile(rt.credentialsPath, []byte(`[default]
aws_access_key_id = EXAMPLEDEFAULTACCESS
aws_secret_access_key = EXAMPLEDEFAULTSECRET

[example-develop]
aws_access_key_id = EXAMPLEDEVACCESS
aws_secret_access_key = EXAMPLEDEVSECRET

[example-stage]
aws_access_key_id = EXAMPLESTAGEACCESS
aws_secret_access_key = EXAMPLESTAGESECRET
`), 0o600))
}

func buildAcceptanceBinary(t *testing.T, rt *acceptanceRuntime) {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	assert.Assert(t, ok)

	build := exec.Command("go", "build", "-o", rt.binaryPath, ".")
	build.Dir = filepath.Dir(sourceFile)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	buildOutput, err := build.CombinedOutput()
	assert.NilError(t, err, string(buildOutput))
}

func newAcceptanceCommand(t *testing.T, rt *acceptanceRuntime, args ...string) (*exec.Cmd, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	command := exec.CommandContext(ctx, rt.binaryPath, args...)
	command.Env = append([]string(nil), rt.env...)
	return command, cancel
}

func runAcceptanceInteractive(t *testing.T, rt *acceptanceRuntime, steps []acceptancePromptStep) string {
	t.Helper()
	command, cancel := newAcceptanceCommand(t, rt)
	defer cancel()

	terminal, err := pty.Start(command)
	assert.NilError(t, err)
	defer terminal.Close()

	var output bytes.Buffer
	for _, step := range steps {
		assert.NilError(t, readUntil(terminal, &output, step.marker))
		_, err := terminal.Write([]byte(step.input))
		assert.NilError(t, err)
	}
	assert.NilError(t, command.Wait(), output.String())
	return output.String()
}

func runAcceptanceCredentialProcess(t *testing.T, rt *acceptanceRuntime, profileName string) map[string]interface{} {
	t.Helper()
	args := []string{"credential-process"}
	if profileName != "" {
		args = append(args, "--profile", profileName)
	}
	command, cancel := newAcceptanceCommand(t, rt, args...)
	defer cancel()

	output, err := command.CombinedOutput()
	assert.NilError(t, err, string(output))
	var payload map[string]interface{}
	assert.NilError(t, json.Unmarshal(output, &payload))
	return payload
}

func assertAcceptanceConfig(t *testing.T, rt *acceptanceRuntime, selectedProfile string) {
	t.Helper()
	config, err := ini.Load(rt.configPath)
	assert.NilError(t, err)

	for _, sectionName := range []string{"default", "profile " + selectedProfile} {
		process := config.Section(sectionName).Key("credential_process").String()
		assert.Assert(t, strings.Contains(process, "credential-process --profile "+selectedProfile), process)
	}
}

func assertAcceptanceCredentialProcess(t *testing.T, payload map[string]interface{}, accessKey, secretKey string) {
	t.Helper()
	assert.Equal(t, payload["Version"], float64(1))
	assert.Equal(t, payload["AccessKeyId"], accessKey)
	assert.Equal(t, payload["SecretAccessKey"], secretKey)
}

func TestAcceptanceBlackBoxInteractiveProfileLifecycle(t *testing.T) {
	cases := []struct {
		name         string
		cleanupInput string
		profileInput string
		restartInput string
		selected     string
		accessKey    string
		secretKey    string
		wantBackup   bool
	}{
		{
			name:         "delete source and select development profile",
			cleanupInput: "\r",
			profileInput: "\x1b[B\r",
			restartInput: "\x1b[B\r",
			selected:     "example-develop",
			accessKey:    "EXAMPLEDEVACCESS",
			secretKey:    "EXAMPLEDEVSECRET",
		},
		{
			name:         "keep backup and select staging profile",
			cleanupInput: "\x1b[B\r",
			profileInput: "\x1b[B\x1b[B\r",
			restartInput: "\x1b[B\x1b[B\r",
			selected:     "example-stage",
			accessKey:    "EXAMPLESTAGEACCESS",
			secretKey:    "EXAMPLESTAGESECRET",
			wantBackup:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newAcceptanceRuntime(t, "")
			writeAcceptanceFixture(t, rt)
			buildAcceptanceBinary(t, rt)

			output := runAcceptanceInteractive(t, rt, []acceptancePromptStep{
				{marker: "Legacy credentials file detected", input: tc.cleanupInput},
				{marker: "Select Profile", input: tc.profileInput},
				{marker: "Select Action", input: "\r"},
			})
			assert.Assert(t, strings.Contains(output, fmt.Sprintf("choose profile [%q]", tc.selected)), output)
			assert.Assert(t, !strings.Contains(output, "Missing Region"), output)

			_, sourceErr := os.Stat(rt.credentialsPath)
			assert.Assert(t, os.IsNotExist(sourceErr))
			_, backupErr := os.Stat(rt.credentialsPath + ".actool-backup")
			if tc.wantBackup {
				assert.NilError(t, backupErr)
			} else {
				assert.Assert(t, os.IsNotExist(backupErr))
			}

			assertAcceptanceConfig(t, rt, tc.selected)
			assertAcceptanceCredentialProcess(t, runAcceptanceCredentialProcess(t, rt, ""), tc.accessKey, tc.secretKey)
			assertAcceptanceCredentialProcess(t, runAcceptanceCredentialProcess(t, rt, tc.selected), tc.accessKey, tc.secretKey)

			restartOutput := runAcceptanceInteractive(t, rt, []acceptancePromptStep{
				{marker: "Select Profile", input: tc.restartInput},
				{marker: "Select Action", input: "\r"},
			})
			assert.Assert(t, !strings.Contains(restartOutput, "Legacy credentials file detected"), restartOutput)
			assert.Assert(t, strings.Contains(restartOutput, fmt.Sprintf("choose profile [%q]", tc.selected)), restartOutput)
		})
	}
}

func TestAcceptanceBlackBoxInteractiveSessionTokenUsesDefaultRegion(t *testing.T) {
	var (
		mu       sync.Mutex
		requests []string
		auth     []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NilError(t, err)

		mu.Lock()
		requests = append(requests, string(body))
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()

		w.Header().Set("Content-Type", "text/xml")
		switch {
		case strings.Contains(string(body), "Action=GetCallerIdentity"):
			_, _ = io.WriteString(w, `<?xml version="1.0"?><GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/example-user</Arn><UserId>EXAMPLEUSER</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>EXAMPLEREQUEST</RequestId></ResponseMetadata></GetCallerIdentityResponse>`)
		case strings.Contains(string(body), "Action=GetSessionToken"):
			_, _ = io.WriteString(w, `<?xml version="1.0"?><GetSessionTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetSessionTokenResult><Credentials><SessionToken>EXAMPLESESSIONTOKEN</SessionToken><SecretAccessKey>EXAMPLESESSIONSECRET</SecretAccessKey><Expiration>2030-01-02T03:04:05Z</Expiration><AccessKeyId>EXAMPLESESSIONACCESS</AccessKeyId></Credentials></GetSessionTokenResult><ResponseMetadata><RequestId>EXAMPLEREQUEST</RequestId></ResponseMetadata></GetSessionTokenResponse>`)
		default:
			http.Error(w, "unexpected STS operation", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	rt := newAcceptanceRuntime(t, server.URL)
	assert.NilError(t, os.WriteFile(rt.configPath, []byte(`[default]
region = us-west-2

[profile example-develop]
`), 0o600))
	assert.NilError(t, os.WriteFile(rt.credentialsPath, []byte(`[example-develop]
aws_access_key_id = EXAMPLEACCESSKEY
aws_secret_access_key = EXAMPLESECRETKEY
`), 0o600))

	buildAcceptanceBinary(t, rt)
	output := runAcceptanceInteractive(t, rt, []acceptancePromptStep{
		{marker: "Legacy credentials file detected", input: "\r"},
		{marker: "Select Profile", input: "\r"},
		{marker: "Select Action", input: "\x1b[B\r"},
		{marker: "Input MFA Token", input: "123456\r"},
		{marker: "Success get session token.", input: ""},
	})
	assert.Assert(t, !strings.Contains(output, "Missing Region"), output)

	mu.Lock()
	gotRequests := append([]string(nil), requests...)
	gotAuth := append([]string(nil), auth...)
	mu.Unlock()
	assert.Equal(t, len(gotRequests), 2)
	assert.Assert(t, strings.Contains(gotRequests[0], "Action=GetCallerIdentity"))
	assert.Assert(t, strings.Contains(gotRequests[1], "Action=GetSessionToken"))
	assert.Assert(t, strings.Contains(gotRequests[1], "TokenCode=123456"))
	for _, header := range gotAuth {
		assert.Assert(t, strings.Contains(header, "/us-west-2/sts/aws4_request"), header)
	}

	payload := runAcceptanceCredentialProcess(t, rt, "example-develop")
	assertAcceptanceCredentialProcess(t, payload, "EXAMPLESESSIONACCESS", "EXAMPLESESSIONSECRET")
	assert.Equal(t, payload["SessionToken"], "EXAMPLESESSIONTOKEN")
	assert.Equal(t, payload["Expiration"], "2030-01-02T03:04:05Z")
}

func readUntil(reader io.Reader, output *bytes.Buffer, marker string) error {
	buffer := make([]byte, 4096)
	for !bytes.Contains(output.Bytes(), []byte(marker)) {
		read, err := reader.Read(buffer)
		if read > 0 {
			_, _ = output.Write(buffer[:read])
		}
		if err != nil {
			return err
		}
	}
	return nil
}
