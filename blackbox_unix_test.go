//go:build darwin || linux

package main

import (
	"bytes"
	"context"
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
	"gotest.tools/v3/assert"
)

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

	root := t.TempDir()
	home := filepath.Join(root, "home")
	configDir := filepath.Join(home, ".aws")
	configPath := filepath.Join(configDir, "config")
	credentialsPath := filepath.Join(configDir, "credentials")
	storePath := filepath.Join(home, ".awsvault", "keys")
	assert.NilError(t, os.MkdirAll(configDir, 0o700))
	assert.NilError(t, os.WriteFile(configPath, []byte(`[default]
region = us-west-2

[profile example-develop]
`), 0o600))
	assert.NilError(t, os.WriteFile(credentialsPath, []byte(`[example-develop]
aws_access_key_id = EXAMPLEACCESSKEY
aws_secret_access_key = EXAMPLESECRETKEY
`), 0o600))

	binaryPath := filepath.Join(root, "actool")
	_, sourceFile, _, ok := runtime.Caller(0)
	assert.Assert(t, ok)
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Dir = filepath.Dir(sourceFile)
	buildOutput, err := build.CombinedOutput()
	assert.NilError(t, err, string(buildOutput))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binaryPath)
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"AWS_CONFIG_FILE=" + configPath,
		"AWS_SHARED_CREDENTIALS_FILE=" + credentialsPath,
		"AWS_VAULT_BACKEND=file",
		"AWS_VAULT_FILE_DIR=" + storePath,
		"AWS_VAULT_FILE_PASSPHRASE=example-passphrase",
		"AWS_ENDPOINT_URL_STS=" + server.URL,
		"AWS_REGION=",
		"AWS_DEFAULT_REGION=",
		"AWS_EC2_METADATA_DISABLED=true",
		"TERM=xterm",
	}

	terminal, err := pty.Start(command)
	assert.NilError(t, err)
	defer terminal.Close()

	var output bytes.Buffer
	waitFor := func(marker string) {
		t.Helper()
		assert.NilError(t, readUntil(terminal, &output, marker))
	}
	send := func(input string) {
		t.Helper()
		_, err := terminal.Write([]byte(input))
		assert.NilError(t, err)
	}

	waitFor("Legacy credentials file detected")
	send("\r")
	waitFor("Select Profile")
	send("\r")
	waitFor("Select Action")
	send("\x1b[B\r")
	waitFor("Input MFA Token")
	send("123456\r")
	waitFor("Success get session token.")

	assert.NilError(t, command.Wait(), output.String())
	assert.Assert(t, !strings.Contains(output.String(), "Missing Region"), output.String())

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
