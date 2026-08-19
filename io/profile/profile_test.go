package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"gopkg.in/ini.v1"
	"gotest.tools/v3/assert"
)

type fakeSecretStore struct {
	values      map[string][]byte
	failSetKey  string
	failSetErr  error
	setCallKeys []string
}

func newFakeSecretStore() *fakeSecretStore {
	return &fakeSecretStore{values: make(map[string][]byte)}
}

func (f *fakeSecretStore) Get(key string) ([]byte, error) {
	value, ok := f.values[key]
	if !ok {
		return nil, errSecretNotFound
	}
	return append([]byte(nil), value...), nil
}

func (f *fakeSecretStore) Set(key string, value []byte) error {
	f.setCallKeys = append(f.setCallKeys, key)
	if key == f.failSetKey {
		if f.failSetErr != nil {
			return f.failSetErr
		}
		return errors.New("secret store set failed")
	}
	f.values[key] = append([]byte(nil), value...)
	return nil
}

func (f *fakeSecretStore) Remove(key string) error {
	if _, ok := f.values[key]; !ok {
		return errSecretNotFound
	}
	delete(f.values, key)
	return nil
}

func (f *fakeSecretStore) Keys() ([]string, error) {
	keys := make([]string, 0, len(f.values))
	for key := range f.values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func newTestProfile(t *testing.T, store *fakeSecretStore) *profile {
	t.Helper()
	dir := t.TempDir()
	return newProfile(
		filepath.Join(dir, "config"),
		filepath.Join(dir, "credentials"),
		"actool",
		store,
		nil,
	)
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	assert.NilError(t, os.WriteFile(path, []byte(contents), 0o600))
}

func storeBaseCredential(t *testing.T, p *profile, name, accessKey, secretKey string, expiration *time.Time) {
	t.Helper()
	assert.NilError(t, p.storeCredential(baseCredentialKeyPrefix, name, &Credential{
		Name:       name,
		AccessKey:  accessKey,
		SecretKey:  secretKey,
		Expiration: expiration,
	}))
}

func storeFutureSession(t *testing.T, p *profile, name string, expiration time.Time) {
	t.Helper()
	assert.NilError(t, p.storeSessionCredential(&Credential{
		Name:         name,
		AccessKey:    "SESSIONACCESSKEY",
		SecretKey:    "SESSIONSECRETKEY",
		SessionToken: "SESSIONTOKEN",
		Expiration:   &expiration,
	}))
}

func credentialNames(credentials []*Credential) []string {
	result := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		result = append(result, credential.Name)
	}
	sort.Strings(result)
	return result
}

func credentialProcessJSON(t *testing.T, payload []byte) map[string]interface{} {
	t.Helper()
	var value map[string]interface{}
	assert.NilError(t, json.Unmarshal(payload, &value))
	return value
}

func TestProfileLoadMigratesLegacyCredentialsAndSyncsConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	credentialsPath := filepath.Join(dir, "credentials")

	writeTestFile(t, configPath, `
[default]
region = ap-northeast-1
output = json

[profile AWS Account Dev]
region = us-west-2
output = yaml
`)
	writeTestFile(t, credentialsPath, `
[default]
aws_access_key_id = DEVACCESSKEY
aws_secret_access_key = DEVSECRETKEY
original_aws_access_key_id = DEFAULTACCESSKEY
original_aws_secret_access_key = DEFAULTSECRETKEY

[AWS Account Dev]
aws_access_key_id = DEVACCESSKEY
aws_secret_access_key = DEVSECRETKEY
`)

	promptCalls := 0
	p := newProfile(configPath, credentialsPath, "actool", newFakeSecretStore(), func(path string) (bool, error) {
		promptCalls++
		assert.Equal(t, path, credentialsPath)
		return false, nil
	})

	model, err := p.Load()
	assert.NilError(t, err)
	assert.Equal(t, model.SelectedProfile, "AWS Account Dev")
	assert.DeepEqual(t, credentialNames(model.Credentials), []string{"AWS Account Dev", "default"})

	payload, err := p.CredentialProcessPayload("")
	assert.NilError(t, err)
	assert.DeepEqual(t, credentialProcessJSON(t, payload), map[string]interface{}{
		"Version":         float64(1),
		"AccessKeyId":     "DEVACCESSKEY",
		"SecretAccessKey": "DEVSECRETKEY",
	})

	_, statErr := os.Stat(credentialsPath)
	assert.Assert(t, os.IsNotExist(statErr))
	_, backupErr := os.Stat(credentialsPath + ".actool-backup")
	assert.NilError(t, backupErr)
	assert.Equal(t, promptCalls, 1)

	assert.NilError(t, p.SetSelected("default"))
	model, err = p.Load()
	assert.NilError(t, err)
	assert.Equal(t, model.SelectedProfile, "default")
	assert.Equal(t, promptCalls, 1)

	writeTestFile(t, credentialsPath, `
[default]
aws_access_key_id = NEWDEFAULTACCESSKEY
aws_secret_access_key = NEWDEFAULTSECRETKEY
`)
	_, err = p.Load()
	assert.NilError(t, err)
	assert.Equal(t, promptCalls, 2)
	_, backupErr = os.Stat(credentialsPath + ".actool-backup-1")
	assert.NilError(t, backupErr)

	configFile, err := ini.Load(configPath)
	assert.NilError(t, err)
	assert.Equal(t, configFile.Section("default").Key(CredentialProcess).String(), "actool credential-process --profile default")
	assert.Equal(t, configFile.Section("default").Key(Region).String(), "us-west-2")
	assert.Equal(t, configFile.Section("default").Key(Output).String(), "yaml")
	assert.Equal(t, configFile.Section("profile AWS Account Dev").Key(CredentialProcess).String(), "actool credential-process --profile 'AWS Account Dev'")
}

func TestProfileLoadRemovesLegacyCredentialsSource(t *testing.T) {
	cases := []struct {
		name          string
		deleteSource  bool
		backupPresent bool
	}{
		{name: "delete", deleteSource: true, backupPresent: false},
		{name: "move to backup", deleteSource: false, backupPresent: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config")
			credentialsPath := filepath.Join(dir, "credentials")
			writeTestFile(t, configPath, "[default]\nregion = ap-northeast-1\n")
			writeTestFile(t, credentialsPath, "[default]\naws_access_key_id = DEFAULTACCESSKEY\naws_secret_access_key = DEFAULTSECRETKEY\n")

			p := newProfile(configPath, credentialsPath, "actool", newFakeSecretStore(), func(path string) (bool, error) {
				assert.Equal(t, path, credentialsPath)
				return tc.deleteSource, nil
			})

			_, err := p.Load()
			assert.NilError(t, err)
			_, sourceErr := os.Stat(credentialsPath)
			assert.Assert(t, os.IsNotExist(sourceErr))

			_, backupErr := os.Stat(credentialsPath + ".actool-backup")
			if tc.backupPresent {
				assert.NilError(t, backupErr)
			} else {
				assert.Assert(t, os.IsNotExist(backupErr))
			}
		})
	}
}

func TestCredentialProcessPayloadResolution(t *testing.T) {
	future := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	basePayload := map[string]interface{}{
		"Version":         float64(1),
		"AccessKeyId":     "BASEACCESSKEY",
		"SecretAccessKey": "BASESECRETKEY",
	}
	sessionPayload := map[string]interface{}{
		"Version":         float64(1),
		"AccessKeyId":     "SESSIONACCESSKEY",
		"SecretAccessKey": "SESSIONSECRETKEY",
		"SessionToken":    "SESSIONTOKEN",
		"Expiration":      future.Format(time.RFC3339),
	}

	cases := []struct {
		name        string
		profileName string
		setup       func(t *testing.T, p *profile, store *fakeSecretStore)
		wantPayload map[string]interface{}
		wantErr     string
	}{
		{
			name:        "explicit base credential",
			profileName: "dev",
			setup: func(t *testing.T, p *profile, _ *fakeSecretStore) {
				storeBaseCredential(t, p, "dev", "BASEACCESSKEY", "BASESECRETKEY", nil)
			},
			wantPayload: basePayload,
		},
		{
			name: "selected base credential",
			setup: func(t *testing.T, p *profile, _ *fakeSecretStore) {
				storeBaseCredential(t, p, "dev", "BASEACCESSKEY", "BASESECRETKEY", nil)
				assert.NilError(t, p.SetSelected("dev"))
			},
			wantPayload: basePayload,
		},
		{
			name:        "stored session credential",
			profileName: "dev",
			setup: func(t *testing.T, p *profile, _ *fakeSecretStore) {
				storeBaseCredential(t, p, "dev", "BASEACCESSKEY", "BASESECRETKEY", nil)
				assert.NilError(t, p.SetSelected("dev"))
				storeFutureSession(t, p, "dev", future)
			},
			wantPayload: sessionPayload,
		},
		{
			name:        "expired session does not fall back to base",
			profileName: "dev",
			setup: func(t *testing.T, p *profile, _ *fakeSecretStore) {
				storeBaseCredential(t, p, "dev", "BASEACCESSKEY", "BASESECRETKEY", nil)
				assert.NilError(t, p.SetSelected("dev"))
				expired := time.Now().UTC().Add(-time.Minute)
				assert.NilError(t, p.storeSessionCredential(&Credential{
					Name:         "dev",
					AccessKey:    "SESSIONACCESSKEY",
					SecretKey:    "SESSIONSECRETKEY",
					SessionToken: "SESSIONTOKEN",
					Expiration:   &expired,
				}))
			},
			wantErr: "have expired",
		},
		{
			name:        "expired base credential",
			profileName: "dev",
			setup: func(t *testing.T, p *profile, _ *fakeSecretStore) {
				expired := time.Now().UTC().Add(-time.Minute)
				storeBaseCredential(t, p, "dev", "BASEACCESSKEY", "BASESECRETKEY", &expired)
			},
			wantErr: "have expired",
		},
		{
			name: "selected profile is required for implicit lookup",
			setup: func(t *testing.T, p *profile, _ *fakeSecretStore) {
				storeBaseCredential(t, p, "dev", "BASEACCESSKEY", "BASESECRETKEY", nil)
			},
			wantErr: "not initialized",
		},
		{
			name:        "missing profile",
			profileName: "missing",
			setup:       func(*testing.T, *profile, *fakeSecretStore) {},
			wantErr:     "profile not found",
		},
		{
			name:        "malformed session without token fails closed",
			profileName: "dev",
			setup: func(t *testing.T, p *profile, store *fakeSecretStore) {
				storeBaseCredential(t, p, "dev", "BASEACCESSKEY", "BASESECRETKEY", nil)
				assert.NilError(t, p.SetSelected("dev"))
				assert.NilError(t, store.Set(sessionKey(sessionMetadata{
					Type:        sessionTypeGetSession,
					ProfileName: "dev",
					Expiration:  future,
				}), []byte(`{"AccessKeyId":"SESSIONACCESSKEY","SecretAccessKey":"SESSIONSECRETKEY","Expiration":"2030-01-02T03:04:05Z"}`)))
			},
			wantErr: "no session token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeSecretStore()
			p := newTestProfile(t, store)
			tc.setup(t, p, store)

			payload, err := p.CredentialProcessPayload(tc.profileName)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			assert.NilError(t, err)
			assert.DeepEqual(t, credentialProcessJSON(t, payload), tc.wantPayload)
		})
	}
}

func TestStoreSessionTokenValidation(t *testing.T) {
	future := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name       string
		hasBase    bool
		credential func() *Credential
		wantErr    string
	}{
		{name: "nil credential", hasBase: true, credential: func() *Credential { return nil }, wantErr: "credential is nil"},
		{name: "missing expiration", hasBase: true, credential: func() *Credential { return &Credential{AccessKey: "A", SecretKey: "S", SessionToken: "T"} }, wantErr: "missing a future expiration"},
		{name: "expired credential", hasBase: true, credential: func() *Credential {
			expired := time.Now().UTC().Add(-time.Minute)
			return &Credential{AccessKey: "A", SecretKey: "S", SessionToken: "T", Expiration: &expired}
		}, wantErr: "missing a future expiration"},
		{name: "missing access key", hasBase: true, credential: func() *Credential { return &Credential{SecretKey: "S", SessionToken: "T", Expiration: &future} }, wantErr: "credential is incomplete"},
		{name: "missing secret key", hasBase: true, credential: func() *Credential { return &Credential{AccessKey: "A", SessionToken: "T", Expiration: &future} }, wantErr: "credential is incomplete"},
		{name: "missing session token", hasBase: true, credential: func() *Credential { return &Credential{AccessKey: "A", SecretKey: "S", Expiration: &future} }, wantErr: "credential is incomplete"},
		{name: "base profile missing", hasBase: false, credential: func() *Credential {
			return &Credential{AccessKey: "A", SecretKey: "S", SessionToken: "T", Expiration: &future}
		}, wantErr: "profile not found"},
		{name: "valid", hasBase: true, credential: func() *Credential {
			return &Credential{AccessKey: "A", SecretKey: "S", SessionToken: "T", Expiration: &future}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeSecretStore()
			p := newTestProfile(t, store)
			if tc.hasBase {
				storeBaseCredential(t, p, "dev", "BASEACCESSKEY", "BASESECRETKEY", nil)
			}

			err := p.StoreSessionToken("dev", tc.credential())
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			assert.NilError(t, err)
			state, stateErr := p.loadState()
			assert.NilError(t, stateErr)
			assert.Equal(t, state.SelectedProfile, "dev")
			stored, expired, sessionErr := p.sessionCredentialForProfile("dev")
			assert.NilError(t, sessionErr)
			assert.Assert(t, stored != nil)
			assert.Assert(t, !expired)
			assert.Equal(t, stored.SessionToken, "T")
		})
	}
}

func TestConfigAndCredentialLookup(t *testing.T) {
	store := newFakeSecretStore()
	p := newTestProfile(t, store)
	storeBaseCredential(t, p, Default, "DEFAULTACCESSKEY", "DEFAULTSECRETKEY", nil)
	storeBaseCredential(t, p, "dev", "DEVACCESSKEY", "DEVSECRETKEY", nil)

	model := &Model{Configs: []*Config{
		{Name: Default, Region: "ap-northeast-1"},
		{Name: "dev", Region: "us-west-2"},
	}}

	credentialCases := []struct {
		name    string
		wantKey string
		wantErr string
	}{
		{name: Default, wantKey: "DEFAULTACCESSKEY"},
		{name: "dev", wantKey: "DEVACCESSKEY"},
		{name: "missing", wantErr: "profile not found"},
	}
	for _, tc := range credentialCases {
		t.Run("credential/"+tc.name, func(t *testing.T) {
			credential, err := p.Credential(tc.name)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			assert.NilError(t, err)
			assert.Equal(t, credential.AccessKey, tc.wantKey)
		})
	}

	configCases := []struct {
		name       string
		wantRegion string
	}{
		{name: Default, wantRegion: "ap-northeast-1"},
		{name: "dev", wantRegion: "us-west-2"},
		{name: "missing", wantRegion: "ap-northeast-1"},
	}
	for _, tc := range configCases {
		t.Run("config/"+tc.name, func(t *testing.T) {
			config, err := p.Config(model, tc.name)
			assert.NilError(t, err)
			assert.Equal(t, config.Region, tc.wantRegion)
		})
	}

	_, err := p.Config(nil, Default)
	assert.ErrorContains(t, err, "model is nil")
}

func TestStoresAWSVaultCompatibleCredentialData(t *testing.T) {
	cases := []struct {
		name       string
		credential Credential
		wantKey    string
		wantValue  string
	}{
		{
			name:       "base credential",
			credential: Credential{Name: "dev", AccessKey: "ACCESSKEY", SecretKey: "SECRETKEY"},
			wantKey:    "AccessKeyID",
			wantValue:  "ACCESSKEY",
		},
		{
			name:       "session credential",
			credential: Credential{Name: "dev", AccessKey: "SESSIONACCESSKEY", SecretKey: "SESSIONSECRETKEY", SessionToken: "SESSIONTOKEN", Expiration: func() *time.Time { value := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC); return &value }()},
			wantKey:    "AccessKeyId",
			wantValue:  "SESSIONACCESSKEY",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeSecretStore()
			p := newTestProfile(t, store)
			credential := tc.credential
			if credential.Expiration == nil {
				assert.NilError(t, p.storeCredential(baseCredentialKeyPrefix, credential.Name, &credential))
			} else {
				assert.NilError(t, p.storeSessionCredential(&credential))
			}

			key := credential.Name
			if credential.Expiration != nil {
				key = sessionKey(sessionMetadata{Type: sessionTypeGetSession, ProfileName: credential.Name, Expiration: credential.Expiration.UTC()})
			}
			raw, err := store.Get(key)
			assert.NilError(t, err)
			value := credentialProcessJSON(t, raw)
			assert.Equal(t, value[tc.wantKey], tc.wantValue)
		})
	}
}

func TestExplicitFileBackendRoundTripsCredential(t *testing.T) {
	t.Setenv("AWS_VAULT_BACKEND", "file")
	t.Setenv("AWS_VAULT_FILE_DIR", t.TempDir())
	t.Setenv("AWS_VAULT_FILE_PASSPHRASE", "test-passphrase")

	store, err := openAWSVaultStore()
	assert.NilError(t, err)
	assert.NilError(t, store.Set("dev", []byte(`{"AccessKeyID":"ACCESSKEY","SecretAccessKey":"SECRETKEY"}`)))

	value, err := store.Get("dev")
	assert.NilError(t, err)
	assert.DeepEqual(t, credentialProcessJSON(t, value), map[string]interface{}{
		"AccessKeyID":     "ACCESSKEY",
		"SecretAccessKey": "SECRETKEY",
	})
}

func TestRuntimeProfileConstructorsUseIsolatedAWSVaultStore(t *testing.T) {
	cases := []struct {
		name        string
		constructor func() (Profile, error)
	}{
		{name: "standard profile", constructor: func() (Profile, error) { return NewProfile() }},
		{name: "interactive profile", constructor: func() (Profile, error) {
			return NewInteractiveProfile(nil)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, ".aws", "config"))
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, ".aws", "credentials"))
			t.Setenv("AWS_VAULT_BACKEND", "file")
			t.Setenv("AWS_VAULT_FILE_DIR", filepath.Join(home, "aws-vault"))
			t.Setenv("AWS_VAULT_FILE_PASSPHRASE", "test-passphrase")

			legacyStore, err := openLegacyActoolStore()
			assert.NilError(t, err)
			assert.NilError(t, legacyStore.Set("unused", []byte("legacy namespace remains available")))

			p, err := tc.constructor()
			assert.NilError(t, err)
			model, err := p.Load()
			assert.NilError(t, err)
			assert.DeepEqual(t, model.Credentials, []*Credential{})
		})
	}
}

func TestOpenKeyringRejectsUnknownBackend(t *testing.T) {
	_, err := openKeyring(keyring.Config{
		AllowedBackends: []keyring.BackendType{"invalid-backend"},
	})
	assert.Assert(t, err != nil)
}

func TestSecureBackendsDoNotImplicitlySelectPass(t *testing.T) {
	backends := secureBackends()
	for _, backend := range backends {
		assert.Assert(t, backend != keyring.PassBackend)
	}

	available := keyring.AvailableBackends()
	fileAvailable := false
	for _, backend := range available {
		if backend == keyring.FileBackend {
			fileAvailable = true
			break
		}
	}
	if fileAvailable {
		assert.Assert(t, len(backends) > 0)
		assert.Equal(t, backends[len(backends)-1], keyring.FileBackend)
	}
}

func TestFileKeyringPasswordRejectsEmptyEnvironmentValue(t *testing.T) {
	t.Setenv("AWS_VAULT_FILE_PASSPHRASE", "")
	_, err := fileKeyringPassword("unused")
	assert.ErrorContains(t, err, "must not be empty")
}

func TestFileKeyringPasswordUsesEnvironmentValue(t *testing.T) {
	t.Setenv("AWS_VAULT_FILE_PASSPHRASE", "test-passphrase")

	password, err := fileKeyringPassword("unused")
	assert.NilError(t, err)
	assert.Equal(t, password, "test-passphrase")
}

func TestAWSVaultKeyringConfig(t *testing.T) {
	cases := []struct {
		name   string
		legacy bool
		setup  func(*testing.T)
		check  func(*testing.T, keyring.Config)
	}{
		{
			name: "aws vault defaults",
			check: func(t *testing.T, config keyring.Config) {
				assert.Equal(t, config.ServiceName, awsVaultServiceName)
				assert.Equal(t, config.KeychainName, "aws-vault")
				assert.Equal(t, config.LibSecretCollectionName, "awsvault")
				assert.Equal(t, config.KWalletAppID, "aws-vault")
				assert.Equal(t, config.KWalletFolder, "aws-vault")
				assert.Equal(t, config.WinCredPrefix, "aws-vault")
				assert.Equal(t, config.FileDir, "~/.awsvault/keys/")
				assert.Assert(t, config.FilePasswordFunc != nil)
				assert.Equal(t, config.AllowedBackends[len(config.AllowedBackends)-1], keyring.FileBackend)
			},
		},
		{
			name: "explicit backend and compatibility environment",
			setup: func(t *testing.T) {
				t.Setenv("AWS_VAULT_BACKEND", "file")
				t.Setenv("AWS_VAULT_FILE_DIR", "/tmp/aws-vault-keys")
				t.Setenv("AWS_VAULT_KEYCHAIN_NAME", "custom-keychain")
				t.Setenv("AWS_VAULT_SECRET_SERVICE_COLLECTION_NAME", "custom-collection")
				t.Setenv("AWS_VAULT_PASS_PASSWORD_STORE_DIR", "/tmp/password-store")
				t.Setenv("AWS_VAULT_PASS_CMD", "custom-pass")
				t.Setenv("AWS_VAULT_PASS_PREFIX", "custom-prefix")
			},
			check: func(t *testing.T, config keyring.Config) {
				assert.Equal(t, config.ServiceName, awsVaultServiceName)
				assert.Equal(t, config.FileDir, "/tmp/aws-vault-keys")
				assert.Equal(t, config.KeychainName, "custom-keychain")
				assert.Equal(t, config.LibSecretCollectionName, "custom-collection")
				assert.Equal(t, config.PassDir, "/tmp/password-store")
				assert.Equal(t, config.PassCmd, "custom-pass")
				assert.Equal(t, config.PassPrefix, "custom-prefix")
				assert.DeepEqual(t, config.AllowedBackends, []keyring.BackendType{keyring.FileBackend})
			},
		},
		{
			name:   "legacy actool namespace",
			legacy: true,
			check: func(t *testing.T, config keyring.Config) {
				assert.Equal(t, config.ServiceName, actoolServiceName)
				assert.Equal(t, config.KeychainName, "")
				assert.Equal(t, config.LibSecretCollectionName, actoolServiceName)
				assert.Equal(t, config.KWalletAppID, "keyring")
				assert.Equal(t, config.KWalletFolder, "keyring")
				assert.Equal(t, config.WinCredPrefix, "")
			},
		},
	}

	envNames := []string{
		"AWS_VAULT_BACKEND",
		"AWS_VAULT_FILE_DIR",
		"AWS_VAULT_KEYCHAIN_NAME",
		"AWS_VAULT_SECRET_SERVICE_COLLECTION_NAME",
		"AWS_VAULT_PASS_PASSWORD_STORE_DIR",
		"AWS_VAULT_PASS_CMD",
		"AWS_VAULT_PASS_PREFIX",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, envName := range envNames {
				t.Setenv(envName, "")
			}
			if tc.setup != nil {
				tc.setup(t)
			}
			tc.check(t, awsVaultKeyringConfig(tc.legacy))
		})
	}
}

func TestLegacyCredentialsAreRemovedBeforeConfigSyncFailure(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	credentialsPath := filepath.Join(dir, "credentials")
	originalConfig := "[default]\ncredential_process = aws-vault exec dev -j\n"
	writeTestFile(t, configPath, originalConfig)
	writeTestFile(t, credentialsPath, "[default]\naws_access_key_id = ACCESSKEY\naws_secret_access_key = SECRETKEY\n")

	store := newFakeSecretStore()
	p := newProfile(configPath, credentialsPath, "actool", store, func(path string) (bool, error) {
		assert.Equal(t, path, credentialsPath)
		return false, nil
	})

	_, err := p.Load()
	assert.ErrorContains(t, err, "different credential_process")
	_, sourceErr := os.Stat(credentialsPath)
	assert.Assert(t, os.IsNotExist(sourceErr))
	_, backupErr := os.Stat(credentialsPath + ".actool-backup")
	assert.NilError(t, backupErr)
	configData, readErr := os.ReadFile(configPath)
	assert.NilError(t, readErr)
	assert.Equal(t, string(configData), originalConfig)
	credential, credentialErr := p.Credential(Default)
	assert.NilError(t, credentialErr)
	assert.Equal(t, credential.AccessKey, "ACCESSKEY")
}

func TestStoreSessionTokenReplacesOnlyMatchingSession(t *testing.T) {
	store := newFakeSecretStore()
	p := newTestProfile(t, store)
	storeBaseCredential(t, p, "dev", "BASEACCESSKEY", "BASESECRETKEY", nil)

	oldExpiration := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	otherExpiration := time.Date(2030, time.February, 2, 3, 4, 5, 0, time.UTC)
	assert.NilError(t, p.storeSessionCredential(&Credential{
		Name:         "dev",
		AccessKey:    "OLDACCESSKEY",
		SecretKey:    "OLDSECRETKEY",
		SessionToken: "OLDTOKEN",
		Expiration:   &oldExpiration,
		MFASerial:    "mfa-1",
	}))
	oldKey := sessionKey(sessionMetadata{Type: sessionTypeGetSession, ProfileName: "dev", MFASerial: "mfa-1", Expiration: oldExpiration})
	assert.NilError(t, p.storeSessionCredential(&Credential{
		Name:         "dev",
		AccessKey:    "OTHERACCESSKEY",
		SecretKey:    "OTHERSECRETKEY",
		SessionToken: "OTHERTOKEN",
		Expiration:   &otherExpiration,
		MFASerial:    "mfa-2",
	}))

	assumeRoleKey := sessionKey(sessionMetadata{Type: "sts.AssumeRole", ProfileName: "dev", MFASerial: "mfa-1", Expiration: otherExpiration})
	assert.NilError(t, store.Set(assumeRoleKey, []byte(`{"AccessKeyId":"ROLEACCESSKEY","SecretAccessKey":"ROLESECRETKEY","SessionToken":"ROLETOKEN","Expiration":"2030-02-02T03:04:05Z"}`)))

	newExpiration := time.Date(2030, time.March, 2, 3, 4, 5, 0, time.UTC)
	assert.NilError(t, p.StoreSessionToken("dev", &Credential{
		AccessKey:    "NEWACCESSKEY",
		SecretKey:    "NEWSECRETKEY",
		SessionToken: "NEWTOKEN",
		Expiration:   &newExpiration,
		MFASerial:    "mfa-1",
	}))

	_, oldErr := store.Get(oldKey)
	assert.ErrorIs(t, oldErr, errSecretNotFound)
	newKey := sessionKey(sessionMetadata{Type: sessionTypeGetSession, ProfileName: "dev", MFASerial: "mfa-1", Expiration: newExpiration})
	newData, newErr := store.Get(newKey)
	assert.NilError(t, newErr)
	assert.Assert(t, len(newData) > 0)
	otherKey := sessionKey(sessionMetadata{Type: sessionTypeGetSession, ProfileName: "dev", MFASerial: "mfa-2", Expiration: otherExpiration})
	_, otherErr := store.Get(otherKey)
	assert.NilError(t, otherErr)
	_, assumeRoleErr := store.Get(assumeRoleKey)
	assert.NilError(t, assumeRoleErr)
}

func TestMigratesPreviousActoolSecureStore(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	legacyCredentialsPath := filepath.Join(dir, "credentials")
	legacyStore := newFakeSecretStore()
	targetStore := newFakeSecretStore()

	legacyBaseData, err := json.Marshal(map[string]interface{}{
		"AccessKey":    "LEGACYACCESSKEY",
		"SecretKey":    "LEGACYSECRETKEY",
		"SessionToken": "",
	})
	assert.NilError(t, err)
	assert.NilError(t, legacyStore.Set(secretKey(baseCredentialKeyPrefix, "dev"), legacyBaseData))
	assert.NilError(t, legacyStore.Set(selectedProfileKey, []byte("dev")))

	p := newConfiguredProfile(
		configPath,
		legacyCredentialsPath,
		"actool",
		targetStore,
		&memoryStateStore{},
		func() (secretStore, error) { return legacyStore, nil },
		nil,
	)

	model, err := p.Load()
	assert.NilError(t, err)
	assert.Equal(t, model.SelectedProfile, "dev")
	assert.DeepEqual(t, credentialNames(model.Credentials), []string{"dev"})

	migrated, err := targetStore.Get("dev")
	assert.NilError(t, err)
	var migratedValue map[string]interface{}
	assert.NilError(t, json.Unmarshal(migrated, &migratedValue))
	assert.Equal(t, migratedValue["AccessKeyID"], "LEGACYACCESSKEY")
	assert.Equal(t, migratedValue["SecretAccessKey"], "LEGACYSECRETKEY")

	_, err = p.Load()
	assert.NilError(t, err)
}

func TestMigratesLegacySessionCredentials(t *testing.T) {
	dir := t.TempDir()
	legacyStore := newFakeSecretStore()
	targetStore := newFakeSecretStore()
	configPath := filepath.Join(dir, "config")

	legacyBaseData, err := json.Marshal(map[string]string{
		"AccessKey":    "BASEACCESSKEY",
		"SecretKey":    "BASESECRETKEY",
		"SessionToken": "",
	})
	assert.NilError(t, err)
	assert.NilError(t, legacyStore.Set(secretKey(baseCredentialKeyPrefix, "dev"), legacyBaseData))

	expiration := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	legacySessionData, err := json.Marshal(map[string]interface{}{
		"AccessKey":    "SESSIONACCESSKEY",
		"SecretKey":    "SESSIONSECRETKEY",
		"SessionToken": "SESSIONTOKEN",
		"Expiration":   expiration,
	})
	assert.NilError(t, err)
	assert.NilError(t, legacyStore.Set(secretKey(sessionCredentialPrefix, "dev"), legacySessionData))
	assert.NilError(t, legacyStore.Set(selectedProfileKey, []byte("dev")))

	p := newConfiguredProfile(configPath, filepath.Join(dir, "credentials"), "actool", targetStore, &memoryStateStore{}, func() (secretStore, error) {
		return legacyStore, nil
	}, nil)
	_, err = p.Load()
	assert.NilError(t, err)

	payload, err := p.CredentialProcessPayload("dev")
	assert.NilError(t, err)
	assert.DeepEqual(t, credentialProcessJSON(t, payload), map[string]interface{}{
		"Version":         float64(1),
		"AccessKeyId":     "SESSIONACCESSKEY",
		"SecretAccessKey": "SESSIONSECRETKEY",
		"SessionToken":    "SESSIONTOKEN",
		"Expiration":      expiration.Format(time.RFC3339),
	})
}

func TestDoesNotOverwriteExistingAWSVaultCredentialDuringLegacyMigration(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	targetStore := newFakeSecretStore()
	legacyStore := newFakeSecretStore()
	targetData, err := json.Marshal(map[string]string{
		"AccessKeyID":     "CURRENTACCESSKEY",
		"SecretAccessKey": "CURRENTSECRETKEY",
	})
	assert.NilError(t, err)
	legacyData, err := json.Marshal(map[string]string{
		"AccessKeyID":     "LEGACYACCESSKEY",
		"SecretAccessKey": "LEGACYSECRETKEY",
	})
	assert.NilError(t, err)
	assert.NilError(t, targetStore.Set("dev", targetData))
	assert.NilError(t, legacyStore.Set(secretKey(baseCredentialKeyPrefix, "dev"), legacyData))

	p := newConfiguredProfile(filepath.Join(dir, "config"), filepath.Join(dir, "credentials"), "actool", targetStore, &memoryStateStore{}, func() (secretStore, error) {
		return legacyStore, nil
	}, nil)

	_, err = p.Load()
	assert.ErrorContains(t, err, "conflicts with an existing aws-vault credential")
	stored, err := targetStore.Get("dev")
	assert.NilError(t, err)
	assert.DeepEqual(t, stored, targetData)
}

func TestImportCredentialPlanRollsBackWhenSecretStoreSetFails(t *testing.T) {
	store := newFakeSecretStore()
	store.failSetKey = "b"
	store.failSetErr = errors.New("set b failed")
	p := newTestProfile(t, store)
	plan := map[string]*Credential{
		"a": {Name: "a", AccessKey: "A", SecretKey: "SA"},
		"b": {Name: "b", AccessKey: "B", SecretKey: "SB"},
	}

	err := p.importCredentialPlan(plan)
	assert.ErrorContains(t, err, "set b failed")
	_, aErr := store.Get("a")
	assert.ErrorIs(t, aErr, errSecretNotFound)
	_, bErr := store.Get("b")
	assert.ErrorIs(t, bErr, errSecretNotFound)
}

func TestSyncConfigPreservesUnselectedCredentialSources(t *testing.T) {
	cases := []struct {
		name        string
		key         string
		value       string
		wantProcess string
	}{
		{name: "role", key: "role_arn", value: "arn:aws:iam::123456789012:role/ReadOnly"},
		{name: "source profile", key: "source_profile", value: "base"},
		{name: "credential source", key: "credential_source", value: "Environment"},
		{name: "web identity", key: "web_identity_token_file", value: "/tmp/token"},
		{name: "sso", key: "sso_start_url", value: "https://example.awsapps.com/start"},
		{name: "external process", key: CredentialProcess, value: "aws-vault exec keep -j", wantProcess: "aws-vault exec keep -j"},
		{name: "static credential", key: AWSAccessKeyId, value: "CONFIGACCESSKEY"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config")
			writeTestFile(t, configPath, fmt.Sprintf("[default]\n\n[profile keep]\n%s = %s\n", tc.key, tc.value))
			store := newFakeSecretStore()
			p := newProfile(configPath, filepath.Join(dir, "credentials"), "actool", store, nil)
			storeBaseCredential(t, p, Default, "DEFAULTACCESSKEY", "DEFAULTSECRETKEY", nil)
			storeBaseCredential(t, p, "keep", "KEEPACCESSKEY", "KEEPSECRETKEY", nil)

			_, err := p.Load()
			assert.NilError(t, err)
			config, err := ini.Load(configPath)
			assert.NilError(t, err)
			section := config.Section("profile keep")
			assert.Equal(t, section.Key(tc.key).String(), tc.value)
			assert.Equal(t, section.Key(CredentialProcess).String(), tc.wantProcess)
		})
	}
}

func TestDoesNotOverwriteExternalCredentialProcess(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	original := "[default]\ncredential_process = aws-vault exec dev -j\n"
	writeTestFile(t, configPath, original)
	store := newFakeSecretStore()
	p := newProfile(configPath, filepath.Join(dir, "credentials"), "actool", store, nil)
	storeBaseCredential(t, p, Default, "ACCESSKEY", "SECRETKEY", nil)

	_, err := p.Load()
	assert.ErrorContains(t, err, "different credential_process")
	configData, readErr := os.ReadFile(configPath)
	assert.NilError(t, readErr)
	assert.Equal(t, string(configData), original)
}

func TestDoesNotRewriteStaticCredentialsInAWSConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	original := "[default]\naws_access_key_id = CONFIGACCESSKEY\naws_secret_access_key = CONFIGSECRETKEY\n"
	writeTestFile(t, configPath, original)
	store := newFakeSecretStore()
	p := newProfile(configPath, filepath.Join(dir, "credentials"), "actool", store, nil)
	storeBaseCredential(t, p, Default, "ACCESSKEY", "SECRETKEY", nil)

	_, err := p.Load()
	assert.ErrorContains(t, err, "static credentials in AWS config")
	configData, readErr := os.ReadFile(configPath)
	assert.NilError(t, readErr)
	assert.Equal(t, string(configData), original)
}

func TestDecodeCredential(t *testing.T) {
	expiration := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name    string
		data    string
		want    *Credential
		wantErr string
	}{
		{
			name: "aws vault base shape",
			data: `{"AccessKeyID":"A","SecretAccessKey":"S","SessionToken":"","CanExpire":false,"Expires":"0001-01-01T00:00:00Z"}`,
			want: &Credential{Name: "dev", AccessKey: "A", SecretKey: "S"},
		},
		{
			name: "aws vault session shape",
			data: `{"AccessKeyId":"A","SecretAccessKey":"S","SessionToken":"T","Expiration":"2030-01-02T03:04:05Z"}`,
			want: &Credential{Name: "dev", AccessKey: "A", SecretKey: "S", SessionToken: "T", Expiration: &expiration},
		},
		{
			name: "legacy aliases and numeric expiration",
			data: `{"AccessKey":"A","SecretKey":"S","session_token":"T","CanExpire":true,"Expires":1893553445}`,
			want: &Credential{Name: "dev", AccessKey: "A", SecretKey: "S", SessionToken: "T", Expiration: func() *time.Time { value := time.Unix(1893553445, 0).UTC(); return &value }()},
		},
		{name: "invalid json", data: "{", wantErr: "unexpected end of JSON input"},
		{name: "missing secret", data: `{"AccessKeyID":"A"}`, wantErr: "credential is incomplete"},
		{name: "expiration flag without expiration", data: `{"AccessKeyID":"A","SecretAccessKey":"S","CanExpire":true}`, wantErr: "has no expiration"},
		{name: "invalid expiration", data: `{"AccessKeyID":"A","SecretAccessKey":"S","Expiration":"not-a-time"}`, wantErr: "cannot parse"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			credential, err := decodeCredential([]byte(tc.data), "dev")
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			assert.NilError(t, err)
			assert.DeepEqual(t, credential, tc.want)
		})
	}
}

func TestParseLegacyCredentials(t *testing.T) {
	cases := []struct {
		name     string
		data     string
		want     map[string]*Credential
		selected string
		wantErr  string
	}{
		{
			name: "default original and selected named profile",
			data: `
[default]
aws_access_key_id = SESSIONACCESSKEY
aws_secret_access_key = SESSIONSECRETKEY
aws_session_token = SESSIONTOKEN
original_aws_access_key_id = DEFAULTACCESSKEY
original_aws_secret_access_key = DEFAULTSECRETKEY

[dev]
aws_access_key_id = SESSIONACCESSKEY
aws_secret_access_key = SESSIONSECRETKEY
`,
			want: map[string]*Credential{
				Default: {Name: Default, AccessKey: "DEFAULTACCESSKEY", SecretKey: "DEFAULTSECRETKEY"},
				"dev":   {Name: "dev", AccessKey: "SESSIONACCESSKEY", SecretKey: "SESSIONSECRETKEY"},
			},
			selected: "dev",
		},
		{
			name: "named profiles without default",
			data: "[dev]\naws_access_key_id = A\naws_secret_access_key = S\n",
			want: map[string]*Credential{"dev": {Name: "dev", AccessKey: "A", SecretKey: "S"}},
		},
		{name: "empty sections produce empty plan", data: "[default]\nregion = ap-northeast-1\n", want: map[string]*Credential{}},
		{name: "incomplete credentials", data: "[dev]\naws_access_key_id = A\n", wantErr: "incomplete credential"},
		{name: "session token without access keys", data: "[dev]\naws_session_token = T\n", wantErr: "session token without access keys"},
		{name: "incomplete original credentials", data: "[default]\naws_access_key_id = A\naws_secret_access_key = S\noriginal_aws_access_key_id = OA\n", wantErr: "incomplete credential"},
		{name: "reserved profile name", data: "[credential/base/YQ]\naws_access_key_id = A\naws_secret_access_key = S\n", wantErr: "reserved for secure-store metadata"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, selected, err := parseLegacyCredentials([]byte(tc.data))
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			assert.NilError(t, err)
			assert.Equal(t, selected, tc.selected)
			assert.DeepEqual(t, plan, tc.want)
		})
	}
}

func TestParseSessionKey(t *testing.T) {
	expiration := time.Unix(2000000000, 0).UTC()
	currentKey := sessionKey(sessionMetadata{
		Type:        "sts.AssumeRole",
		ProfileName: "AWS Account Dev",
		MFASerial:   "arn:aws:iam::123456789012:mfa/user",
		Expiration:  expiration,
	})
	cases := []struct {
		name     string
		key      string
		want     sessionMetadata
		wantOkay bool
	}{
		{
			name: "current aws vault format",
			key:  currentKey,
			want: sessionMetadata{Type: "sts.AssumeRole", ProfileName: "AWS Account Dev", MFASerial: "arn:aws:iam::123456789012:mfa/user", Expiration: expiration}, wantOkay: true,
		},
		{
			name: "old comma format",
			key:  "session,dev,arn:aws:iam::123456789012:mfa/user,2000000000",
			want: sessionMetadata{Type: sessionTypeGetSession, ProfileName: "dev", MFASerial: "arn:aws:iam::123456789012:mfa/user", Expiration: expiration}, wantOkay: true,
		},
		{
			name: "old colon format",
			key:  "session:dev:arn:aws:iam::123456789012:mfa/user:2000000000",
			want: sessionMetadata{Type: sessionTypeGetSession, ProfileName: "dev", MFASerial: "arn:aws:iam::123456789012:mfa/user", Expiration: expiration}, wantOkay: true,
		},
		{
			name: "old display format",
			key:  "dev session (2000000000)",
			want: sessionMetadata{Type: sessionTypeGetSession, ProfileName: "dev", Expiration: expiration}, wantOkay: true,
		},
		{name: "invalid base64", key: "sts.GetSessionToken,!,,2000000000"},
		{name: "invalid expiration", key: "sts.GetSessionToken,ZGV2,,not-a-number"},
		{name: "not a session", key: "dev"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSessionKey(tc.key)
			assert.Equal(t, ok, tc.wantOkay)
			if tc.wantOkay {
				assert.DeepEqual(t, got, tc.want)
			}
		})
	}
}

func TestValidateProfileName(t *testing.T) {
	reservedSession := sessionKey(sessionMetadata{Type: sessionTypeGetSession, ProfileName: "dev", Expiration: time.Unix(2000000000, 0)})
	cases := []struct {
		name  string
		valid bool
	}{
		{name: Default, valid: true},
		{name: "AWS Account Dev", valid: true},
		{name: "dev/role", valid: true},
		{name: "", valid: false},
		{name: " ", valid: false},
		{name: "selected-profile", valid: false},
		{name: "credential/base/YQ", valid: false},
		{name: "oidc:dev", valid: false},
		{name: "dev[prod]", valid: false},
		{name: "dev\nprod", valid: false},
		{name: reservedSession, valid: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProfileName(tc.name)
			assert.Equal(t, err == nil, tc.valid)
		})
	}
}

func TestCommandLineQuotingAndParsing(t *testing.T) {
	posixCases := []struct {
		name  string
		input string
	}{
		{name: "safe", input: "actool"},
		{name: "spaces", input: "AWS Account Dev"},
		{name: "shell syntax", input: "dev; $(touch /tmp/should-not-exist) 'quoted'"},
		{name: "empty", input: ""},
	}
	for _, tc := range posixCases {
		t.Run("posix/"+tc.name, func(t *testing.T) {
			quoted := quotePosixCommandArg(tc.input)
			args, ok := splitPosixCommandLine(quoted)
			assert.Assert(t, ok)
			assert.DeepEqual(t, args, []string{tc.input})
		})
	}

	windowsCases := []struct {
		name  string
		input string
	}{
		{name: "safe", input: "actool"},
		{name: "spaces", input: `C:\Program Files\actool`},
		{name: "quote", input: `a"b`},
		{name: "trailing slash", input: `C:\tmp\`},
		{name: "empty", input: ""},
	}
	for _, tc := range windowsCases {
		t.Run("windows/"+tc.name, func(t *testing.T) {
			quoted := quoteWindowsCommandArg(tc.input)
			args, ok := splitWindowsCommandLine(quoted)
			assert.Assert(t, ok)
			assert.DeepEqual(t, args, []string{tc.input})
		})
	}

	invalidCases := []struct {
		name string
		fn   func(string) ([]string, bool)
	}{
		{name: "posix unmatched quote", fn: splitPosixCommandLine},
		{name: "windows unmatched quote", fn: splitWindowsCommandLine},
	}
	for _, tc := range invalidCases {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			_, ok := tc.fn(`"unterminated`)
			assert.Assert(t, !ok)
		})
	}
}

func TestIsActoolCredentialProcess(t *testing.T) {
	p := newProfile(filepath.Join(t.TempDir(), "config"), "", "/usr/local/bin/actool", newFakeSecretStore(), nil)
	cases := []struct {
		name    string
		command string
		valid   bool
	}{
		{name: "absolute command", command: "/usr/local/bin/actool credential-process --profile dev", valid: true},
		{name: "command name", command: "actool credential-process --profile dev", valid: true},
		{name: "without profile", command: "actool credential-process", valid: true},
		{name: "quoted profile", command: "actool credential-process --profile 'AWS Account Dev'", valid: true},
		{name: "different command", command: "evil-actool credential-process", valid: false},
		{name: "different subcommand", command: "actool exec dev", valid: false},
		{name: "extra argument", command: "actool credential-process --profile dev extra", valid: false},
		{name: "missing profile value", command: "actool credential-process --profile", valid: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, p.isActoolCredentialProcess(tc.command), tc.valid)
		})
	}
}

func TestFileStateStore(t *testing.T) {
	t.Run("round trip and permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nested", "state.json")
		store := &fileStateStore{path: path}
		want := profileState{Version: stateVersion, SelectedProfile: "dev", LegacyCredentialsHash: "hash"}
		assert.NilError(t, store.Save(want))

		got, err := store.Load()
		assert.NilError(t, err)
		assert.DeepEqual(t, got, want)
		info, err := os.Stat(path)
		assert.NilError(t, err)
		assert.Equal(t, info.Mode().Perm(), os.FileMode(0o600))
	})

	cases := []struct {
		name     string
		contents string
		wantErr  error
		contains string
	}{
		{name: "missing", wantErr: errStateNotFound},
		{name: "invalid json", contents: "{", contains: "unexpected end of JSON input"},
		{name: "unsupported version", contents: `{"Version":2}`, contains: "unsupported actool state version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if tc.contents != "" {
				writeTestFile(t, path, tc.contents)
			}
			_, err := (&fileStateStore{path: path}).Load()
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.ErrorContains(t, err, tc.contains)
			}
		})
	}
}

func TestAWSProfilePaths(t *testing.T) {
	cases := []struct {
		name           string
		configEnv      string
		credentialsEnv string
		wantConfig     string
		wantCreds      string
	}{
		{name: "defaults", wantConfig: "/home/user/.aws/config", wantCreds: "/home/user/.aws/credentials"},
		{name: "custom paths", configEnv: "/tmp/config", credentialsEnv: "/tmp/credentials", wantConfig: "/tmp/config", wantCreds: "/tmp/credentials"},
		{name: "custom config only", configEnv: "/tmp/config", wantConfig: "/tmp/config", wantCreds: "/home/user/.aws/credentials"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AWS_CONFIG_FILE", tc.configEnv)
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", tc.credentialsEnv)
			configPath, credentialsPath := awsProfilePaths("/home/user")
			assert.Equal(t, configPath, tc.wantConfig)
			assert.Equal(t, credentialsPath, tc.wantCreds)
		})
	}
}

func TestProfileSectionNameHelpers(t *testing.T) {
	cases := []struct {
		name      string
		section   string
		profile   string
		profileOK bool
	}{
		{name: "default", section: Default, profile: Default, profileOK: true},
		{name: "named", section: "profile AWS Account Dev", profile: "AWS Account Dev", profileOK: true},
		{name: "other section", section: "credentials dev", profileOK: false},
		{name: "reserved profile section", section: "profile credential/base/YQ", profileOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.profile != "" {
				assert.Equal(t, profileSectionName(tc.profile), tc.section)
			}
			got, ok := configProfileName(tc.section)
			assert.Equal(t, got, tc.profile)
			assert.Equal(t, ok, tc.profileOK)
		})
	}
}
