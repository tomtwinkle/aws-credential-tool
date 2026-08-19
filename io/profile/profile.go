package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"gopkg.in/ini.v1"
)

const (
	Default                    = "default"
	AWSAccessKeyId             = "aws_access_key_id"
	AWSSecretAccessKey         = "aws_secret_access_key"
	AWSSessionToken            = "aws_session_token"
	OriginalAWSAccessKeyId     = "original_aws_access_key_id"
	OriginalAWSSecretAccessKey = "original_aws_secret_access_key"
	Region                     = "region"
	Output                     = "output"
	CredentialProcess          = "credential_process"

	defaultCommandName       = "actool"
	awsVaultServiceName      = "aws-vault"
	actoolServiceName        = "actool"
	credentialProcessCommand = "credential-process"
	sessionTypeGetSession    = "sts.GetSessionToken"

	// These prefixes are kept for importing the secure store format used by
	// the previous implementation.
	baseCredentialKeyPrefix  = "credential/base/"
	sessionCredentialPrefix  = "credential/session/"
	selectedProfileKey       = "selected-profile"
	legacyCredentialsHashKey = "legacy-credentials-hash"

	stateVersion = 1
)

var (
	errSecretNotFound = errors.New("secret not found")
	errStateNotFound  = errors.New("state not found")
)

type DeleteLegacyCredentialsPrompt func(path string) (bool, error)

type Profile interface {
	Load() (*Model, error)
	Credential(profileName string) (*Credential, error)
	Config(model *Model, profileName string) (*Config, error)
	SetSelected(profileName string) error
	StoreSessionToken(profileName string, credential *Credential) error
	CredentialProcessPayload(profileName string) ([]byte, error)
}

type profile struct {
	configPath            string
	legacyCredentialsPath string
	commandName           string
	secrets               secretStore
	state                 stateStore
	deletePrompt          DeleteLegacyCredentialsPrompt

	legacyStoreFactory func() (secretStore, error)
	legacyStoreLoaded  bool
}

type Model struct {
	Configs         []*Config
	Credentials     []*Credential
	SelectedProfile string
}

type Config struct {
	Name              string
	Region            string
	Output            string
	CredentialProcess string
}

type Credential struct {
	Name         string
	AccessKey    string
	SecretKey    string
	SessionToken string
	Expiration   *time.Time
	MFASerial    string
}

type secretStore interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
	Remove(key string) error
	Keys() ([]string, error)
}

type keyringStore struct {
	keyring keyring.Keyring
}

type stateStore interface {
	Load() (profileState, error)
	Save(state profileState) error
}

type profileState struct {
	Version               int
	SelectedProfile       string
	LegacyCredentialsHash string
	LegacyCleanupPending  bool
}

type fileStateStore struct {
	path string
}

type memoryStateStore struct {
	state  profileState
	exists bool
}

type sessionMetadata struct {
	Type        string
	ProfileName string
	MFASerial   string
	Expiration  time.Time
}

type pendingLegacyImport struct {
	path             string
	hash             string
	suggestedProfile string
	deleteSource     bool
}

type secretPreviousValue struct {
	key    string
	value  []byte
	exists bool
}

func NewProfile() (Profile, error) {
	return newRuntimeProfile(nil)
}

func NewInteractiveProfile(deletePrompt DeleteLegacyCredentialsPrompt) (Profile, error) {
	return newRuntimeProfile(deletePrompt)
}

// newProfile is kept dependency-injectable for tests and package callers.
func newProfile(configPath, legacyCredentialsPath, commandName string, secrets secretStore, deletePrompt DeleteLegacyCredentialsPrompt) *profile {
	return newConfiguredProfile(
		configPath,
		legacyCredentialsPath,
		commandName,
		secrets,
		&memoryStateStore{},
		nil,
		deletePrompt,
	)
}

func newConfiguredProfile(
	configPath string,
	legacyCredentialsPath string,
	commandName string,
	secrets secretStore,
	state stateStore,
	legacyStoreFactory func() (secretStore, error),
	deletePrompt DeleteLegacyCredentialsPrompt,
) *profile {
	if strings.TrimSpace(commandName) == "" {
		commandName = defaultCommandName
	}
	return &profile{
		configPath:            configPath,
		legacyCredentialsPath: legacyCredentialsPath,
		commandName:           commandName,
		secrets:               secrets,
		state:                 state,
		deletePrompt:          deletePrompt,
		legacyStoreFactory:    legacyStoreFactory,
	}
}

func newRuntimeProfile(deletePrompt DeleteLegacyCredentialsPrompt) (Profile, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configPath, credentialsPath := awsProfilePaths(homeDir)
	secrets, err := openAWSVaultStore()
	if err != nil {
		return nil, err
	}

	return newConfiguredProfile(
		configPath,
		credentialsPath,
		executableCommandName(),
		secrets,
		&fileStateStore{path: defaultStatePath()},
		func() (secretStore, error) {
			if backend := strings.TrimSpace(os.Getenv("AWS_VAULT_BACKEND")); backend == string(keyring.FileBackend) || backend == string(keyring.PassBackend) {
				// These backends do not namespace entries by ServiceName. Reuse the
				// opened store to avoid a second passphrase prompt and to migrate
				// old entries from the same keyring atomically.
				return secrets, nil
			}
			return openLegacyActoolStore()
		},
		deletePrompt,
	), nil
}

func openAWSVaultStore() (secretStore, error) {
	return openKeyring(awsVaultKeyringConfig(false))
}

func openLegacyActoolStore() (secretStore, error) {
	return openKeyring(awsVaultKeyringConfig(true))
}

func openKeyring(config keyring.Config) (secretStore, error) {
	ring, err := keyring.Open(config)
	if err != nil {
		return nil, err
	}
	return &keyringStore{keyring: ring}, nil
}

func awsVaultKeyringConfig(legacy bool) keyring.Config {
	fileDir := os.Getenv("AWS_VAULT_FILE_DIR")
	if fileDir == "" {
		fileDir = "~/.awsvault/keys/"
	}

	config := keyring.Config{
		ServiceName:                    awsVaultServiceName,
		FileDir:                        fileDir,
		FilePasswordFunc:               fileKeyringPassword,
		KeychainName:                   os.Getenv("AWS_VAULT_KEYCHAIN_NAME"),
		KeychainAccessibleWhenUnlocked: true,
		KeychainTrustApplication:       true,
		LibSecretCollectionName:        os.Getenv("AWS_VAULT_SECRET_SERVICE_COLLECTION_NAME"),
		KWalletAppID:                   "aws-vault",
		KWalletFolder:                  "aws-vault",
		PassDir:                        os.Getenv("AWS_VAULT_PASS_PASSWORD_STORE_DIR"),
		PassCmd:                        os.Getenv("AWS_VAULT_PASS_CMD"),
		PassPrefix:                     os.Getenv("AWS_VAULT_PASS_PREFIX"),
		WinCredPrefix:                  "aws-vault",
	}

	if config.KeychainName == "" {
		config.KeychainName = "aws-vault"
	}
	if config.LibSecretCollectionName == "" {
		config.LibSecretCollectionName = "awsvault"
	}

	if legacy {
		config.ServiceName = actoolServiceName
		config.KeychainName = ""
		config.LibSecretCollectionName = actoolServiceName
		config.KWalletAppID = "keyring"
		config.KWalletFolder = "keyring"
		config.WinCredPrefix = ""
	}

	if backend := strings.TrimSpace(os.Getenv("AWS_VAULT_BACKEND")); backend != "" {
		config.AllowedBackends = []keyring.BackendType{keyring.BackendType(backend)}
	} else {
		config.AllowedBackends = secureBackends()
	}
	return config
}

func secureBackends() []keyring.BackendType {
	available := keyring.AvailableBackends()
	result := make([]keyring.BackendType, 0, len(available))
	fileAvailable := false
	for _, backend := range available {
		if backend == keyring.FileBackend {
			fileAvailable = true
			continue
		}
		if backend == keyring.PassBackend {
			continue
		}
		result = append(result, backend)
	}
	if fileAvailable {
		// The file backend is encrypted and passphrase-protected. Keep it as a
		// safe last resort for builds without a native keyring implementation
		// (for example, CGO-disabled macOS artifacts).
		result = append(result, keyring.FileBackend)
	}
	return result
}

func fileKeyringPassword(prompt string) (string, error) {
	if password, ok := os.LookupEnv("AWS_VAULT_FILE_PASSPHRASE"); ok {
		if password == "" {
			return "", errors.New("AWS_VAULT_FILE_PASSPHRASE must not be empty")
		}
		return password, nil
	}
	password, err := keyring.TerminalPrompt(prompt)
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", errors.New("file keyring passphrase must not be empty")
	}
	return password, nil
}

func (p *profile) Load() (*Model, error) {
	legacySelectedProfile, err := p.migrateLegacyActoolStore()
	if err != nil {
		return nil, err
	}

	pendingImport, err := p.prepareLegacyCredentialsImport()
	if err != nil {
		return nil, err
	}

	profileNames, credentials, err := p.loadBaseCredentials()
	if err != nil {
		return nil, err
	}

	state, err := p.loadState()
	if err != nil && !errors.Is(err, errStateNotFound) {
		return nil, err
	}

	selectedProfile := state.SelectedProfile
	if !containsProfile(profileNames, selectedProfile) {
		selectedProfile = ""
		if pendingImport != nil && containsProfile(profileNames, pendingImport.suggestedProfile) {
			selectedProfile = pendingImport.suggestedProfile
		}
		if selectedProfile == "" && containsProfile(profileNames, legacySelectedProfile) {
			selectedProfile = legacySelectedProfile
		}
		if selectedProfile == "" {
			selectedProfile = defaultSelectedProfile(profileNames)
		}
	}

	if len(profileNames) > 0 {
		state.Version = stateVersion
		state.SelectedProfile = selectedProfile
		if pendingImport != nil {
			state.LegacyCredentialsHash = pendingImport.hash
			state.LegacyCleanupPending = true
		}
		if pendingImport != nil {
			if pendingImport.deleteSource {
				if err := removeIfExists(pendingImport.path); err != nil {
					return nil, err
				}
			} else {
				if err := backupLegacyCredentials(pendingImport.path); err != nil {
					return nil, err
				}
			}
			state.LegacyCleanupPending = false
		}

		if err := p.syncConfig(selectedProfile, profileNames); err != nil {
			return nil, err
		}
		if err := p.saveState(state); err != nil {
			return nil, err
		}
	}

	configs, err := p.loadConfigs()
	if err != nil {
		return nil, err
	}
	return &Model{
		Configs:         configs,
		Credentials:     credentials,
		SelectedProfile: selectedProfile,
	}, nil
}

func (p *profile) Credential(profileName string) (*Credential, error) {
	credential, err := p.baseCredential(profileName)
	if err != nil {
		return nil, err
	}
	return credential, nil
}

func (p *profile) Config(model *Model, profileName string) (*Config, error) {
	if model == nil {
		return nil, errors.New("profile model is nil")
	}

	var defaultConfig *Config
	for _, config := range model.Configs {
		if config == nil {
			continue
		}
		if config.Name == Default {
			defaultConfig = config
		}
		if config.Name == profileName {
			return config, nil
		}
	}
	if defaultConfig != nil {
		return defaultConfig, nil
	}
	return nil, fmt.Errorf("profile config not found. [%s]", profileName)
}

func (p *profile) SetSelected(profileName string) error {
	if _, err := p.baseCredential(profileName); err != nil {
		return err
	}

	profileNames, err := p.profileNames()
	if err != nil {
		return err
	}
	if !containsProfile(profileNames, profileName) {
		return fmt.Errorf("profile not found. [%s]", profileName)
	}

	state, err := p.loadState()
	if err != nil && !errors.Is(err, errStateNotFound) {
		return err
	}
	if err := p.syncConfig(profileName, profileNames); err != nil {
		return err
	}

	state.Version = stateVersion
	state.SelectedProfile = profileName
	if err := p.saveState(state); err != nil {
		return err
	}
	return nil
}

func (p *profile) StoreSessionToken(profileName string, credential *Credential) error {
	if credential == nil {
		return errors.New("credential is nil")
	}
	if credential.Expiration == nil || !credential.Expiration.After(time.Now().UTC()) {
		return errors.New("session credential is missing a future expiration")
	}
	if strings.TrimSpace(credential.AccessKey) == "" || strings.TrimSpace(credential.SecretKey) == "" || strings.TrimSpace(credential.SessionToken) == "" {
		return errors.New("session credential is incomplete")
	}
	if _, err := p.baseCredential(profileName); err != nil {
		return err
	}

	credential.Name = profileName
	if err := p.storeSessionCredential(credential); err != nil {
		return err
	}
	return p.SetSelected(profileName)
}

// CredentialProcessPayload is read-only. AWS CLI and SDKs can invoke it
// concurrently and without a terminal, so migration and config rewrites
// belong to the interactive actool command.
func (p *profile) CredentialProcessPayload(profileName string) ([]byte, error) {
	credential, _, err := p.resolveCredential(profileName)
	if err != nil {
		return nil, err
	}

	response := map[string]interface{}{
		"Version":         1,
		"AccessKeyId":     credential.AccessKey,
		"SecretAccessKey": credential.SecretKey,
	}
	if credential.SessionToken != "" {
		response["SessionToken"] = credential.SessionToken
	}
	if credential.Expiration != nil {
		response["Expiration"] = credential.Expiration.UTC().Format(time.RFC3339)
	}
	payload, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func (p *profile) resolveCredential(profileName string) (*Credential, string, error) {
	selectedProfile := strings.TrimSpace(profileName)
	if selectedProfile == "" {
		state, err := p.loadState()
		if err != nil {
			return nil, "", errors.New("actool is not initialized; run actool once before using AWS CLI")
		}
		selectedProfile = state.SelectedProfile
	}
	if selectedProfile == "" {
		return nil, "", errors.New("no AWS profile is selected; run actool once before using AWS CLI")
	}
	if err := validateProfileName(selectedProfile); err != nil {
		return nil, "", err
	}

	session, expired, err := p.sessionCredentialForProfile(selectedProfile)
	if err != nil {
		return nil, "", err
	}
	if session != nil {
		return session, selectedProfile, nil
	}
	if expired {
		return nil, "", fmt.Errorf("session credentials for profile %q have expired; rerun actool", selectedProfile)
	}

	base, err := p.baseCredential(selectedProfile)
	if err != nil {
		return nil, "", err
	}
	if base.Expiration != nil && !base.Expiration.After(time.Now().UTC()) {
		return nil, "", fmt.Errorf("credentials for profile %q have expired; rerun actool", selectedProfile)
	}
	return base, selectedProfile, nil
}

func (p *profile) sessionCredentialForProfile(profileName string) (*Credential, bool, error) {
	keys, err := p.secrets.Keys()
	if err != nil {
		return nil, false, err
	}

	var candidates []*Credential
	expired := false
	now := time.Now().UTC()
	for _, key := range keys {
		metadata, ok := parseSessionKey(key)
		if !ok || metadata.ProfileName != profileName {
			continue
		}

		data, err := p.secrets.Get(key)
		if err != nil {
			return nil, false, err
		}
		credential, err := decodeCredential(data, profileName)
		if err != nil {
			return nil, false, err
		}
		if strings.TrimSpace(credential.SessionToken) == "" {
			return nil, false, fmt.Errorf("session credential has no session token. [%s]", profileName)
		}
		if credential.Expiration == nil || metadata.Expiration.Before(credential.Expiration.UTC()) {
			expiration := metadata.Expiration.UTC()
			credential.Expiration = &expiration
		}
		credential.MFASerial = metadata.MFASerial

		if !credential.Expiration.After(now) {
			expired = true
			continue
		}
		candidates = append(candidates, credential)
	}
	if len(candidates) == 0 {
		return nil, expired, nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Expiration.Before(*candidates[j].Expiration)
	})
	return candidates[len(candidates)-1], false, nil
}

func (p *profile) storeSessionCredential(credential *Credential) error {
	if credential == nil || credential.Expiration == nil {
		return errors.New("session credential is incomplete")
	}
	if strings.TrimSpace(credential.AccessKey) == "" || strings.TrimSpace(credential.SecretKey) == "" || strings.TrimSpace(credential.SessionToken) == "" {
		return errors.New("session credential is incomplete")
	}
	if err := validateProfileName(credential.Name); err != nil {
		return err
	}

	keys, err := p.secrets.Keys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		metadata, ok := parseSessionKey(key)
		if !ok || metadata.Type != sessionTypeGetSession || metadata.ProfileName != credential.Name || metadata.MFASerial != credential.MFASerial {
			continue
		}
		if err := p.removeSecret(key); err != nil {
			return err
		}
	}

	metadata := sessionMetadata{
		Type:        sessionTypeGetSession,
		ProfileName: credential.Name,
		MFASerial:   credential.MFASerial,
		Expiration:  credential.Expiration.UTC(),
	}
	data := map[string]interface{}{
		"AccessKeyId":     credential.AccessKey,
		"SecretAccessKey": credential.SecretKey,
		"SessionToken":    credential.SessionToken,
		"Expiration":      credential.Expiration.UTC(),
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return p.secrets.Set(sessionKey(metadata), encoded)
}

func (p *profile) baseCredential(profileName string) (*Credential, error) {
	if err := validateProfileName(profileName); err != nil {
		return nil, err
	}
	if isNonProfileKey(profileName) {
		return nil, fmt.Errorf("profile not found. [%s]", profileName)
	}
	data, err := p.secrets.Get(profileName)
	if err != nil {
		if errors.Is(err, errSecretNotFound) {
			return nil, fmt.Errorf("profile not found. [%s]", profileName)
		}
		return nil, err
	}
	return decodeCredential(data, profileName)
}

func (p *profile) profileNames() ([]string, error) {
	names, _, err := p.loadBaseCredentials()
	return names, err
}

func (p *profile) loadBaseCredentials() ([]string, []*Credential, error) {
	keys, err := p.secrets.Keys()
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(keys)

	credentialsByName := make(map[string]*Credential)
	for _, key := range keys {
		if isNonProfileKey(key) || validateProfileName(key) != nil {
			continue
		}
		credential, err := p.baseCredential(key)
		if err != nil {
			// aws-vault's keyring may contain OIDC data or sessions.
			continue
		}
		credentialsByName[key] = credential
	}

	names := make([]string, 0, len(credentialsByName))
	for name := range credentialsByName {
		names = append(names, name)
	}
	sortProfileNames(names)
	credentials := make([]*Credential, 0, len(names))
	for _, name := range names {
		credentials = append(credentials, credentialsByName[name])
	}
	return names, credentials, nil
}

func (p *profile) prepareLegacyCredentialsImport() (*pendingLegacyImport, error) {
	legacyBytes, err := os.ReadFile(p.legacyCredentialsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	plan, suggestedProfile, err := parseLegacyCredentials(legacyBytes)
	if err != nil {
		return nil, err
	}
	if len(plan) == 0 {
		return nil, nil
	}

	hash := fingerprintLegacyCredentials(legacyBytes)
	planMatches := p.credentialPlanMatches(plan)

	if !planMatches {
		if err := p.importCredentialPlan(plan); err != nil {
			return nil, err
		}
	}
	pending := &pendingLegacyImport{
		path:             p.legacyCredentialsPath,
		hash:             hash,
		suggestedProfile: suggestedProfile,
	}
	if p.deletePrompt != nil {
		pending.deleteSource, err = p.deletePrompt(p.legacyCredentialsPath)
		if err != nil {
			return nil, err
		}
	}
	return pending, nil
}

func (p *profile) credentialPlanMatches(plan map[string]*Credential) bool {
	for profileName, expected := range plan {
		actual, err := p.baseCredential(profileName)
		if err != nil || !credentialsEqual(actual, expected) {
			return false
		}
	}
	return true
}

func (p *profile) importCredentialPlan(plan map[string]*Credential) error {
	return p.importCredentialPlanWithOptions(plan, true)
}

func (p *profile) importLegacyCredentialPlan(plan map[string]*Credential) error {
	return p.importCredentialPlanWithOptions(plan, false)
}

func (p *profile) importCredentialPlanWithOptions(plan map[string]*Credential, overwrite bool) error {
	names := make([]string, 0, len(plan))
	for name := range plan {
		names = append(names, name)
	}
	sort.Strings(names)

	var previous []secretPreviousValue
	var changed []string
	for _, name := range names {
		credential := plan[name]
		if credential == nil {
			return fmt.Errorf("credential is nil. [%s]", name)
		}
		data := map[string]interface{}{
			"AccessKeyID":     credential.AccessKey,
			"SecretAccessKey": credential.SecretKey,
			"SessionToken":    credential.SessionToken,
			"Source":          "",
			"CanExpire":       credential.Expiration != nil,
			"Expires":         time.Time{},
			"AccountID":       "",
		}
		if credential.Expiration != nil {
			data["Expires"] = credential.Expiration.UTC()
		}
		encoded, err := json.Marshal(data)
		if err != nil {
			return err
		}

		oldValue, oldErr := p.secrets.Get(name)
		if oldErr != nil && !errors.Is(oldErr, errSecretNotFound) {
			return oldErr
		}
		if oldErr == nil {
			oldCredential, decodeErr := decodeCredential(oldValue, name)
			if decodeErr == nil && credentialsEqual(oldCredential, credential) {
				continue
			}
			if !overwrite {
				return fmt.Errorf("legacy credential %q conflicts with an existing aws-vault credential; remove the conflict and run actool again", name)
			}
		}

		previous = append(previous, secretPreviousValue{
			key:    name,
			value:  append([]byte(nil), oldValue...),
			exists: oldErr == nil,
		})
		if err := p.secrets.Set(name, encoded); err != nil {
			if rollbackErr := p.rollbackSecretChanges(previous, changed); rollbackErr != nil {
				return fmt.Errorf("credential import failed and rollback also failed: %w", err)
			}
			return err
		}
		changed = append(changed, name)
	}
	return nil
}

func (p *profile) rollbackSecretChanges(previous []secretPreviousValue, changed []string) error {
	previousByKey := make(map[string]secretPreviousValue, len(previous))
	for _, item := range previous {
		previousByKey[item.key] = item
	}

	var firstErr error
	for i := len(changed) - 1; i >= 0; i-- {
		item, ok := previousByKey[changed[i]]
		if !ok {
			continue
		}
		var err error
		if item.exists {
			err = p.secrets.Set(changed[i], item.value)
		} else {
			err = p.removeSecret(changed[i])
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (p *profile) migrateLegacyActoolStore() (string, error) {
	if p.legacyStoreFactory == nil {
		return "", nil
	}
	store, err := openLegacyStoreOnce(p)
	if err != nil {
		if errors.Is(err, keyring.ErrNoAvailImpl) {
			return "", nil
		}
		return "", err
	}
	if store == nil {
		return "", nil
	}

	keys, err := store.Keys()
	if err != nil {
		if errors.Is(err, errSecretNotFound) {
			return "", nil
		}
		return "", err
	}

	plan := make(map[string]*Credential)
	selectedProfile := ""
	var sessions []*Credential
	for _, key := range keys {
		if key == selectedProfileKey || key == "selected_profile" || key == "selectedProfile" {
			value, getErr := store.Get(key)
			if getErr == nil {
				selectedProfile = strings.TrimSpace(string(value))
			} else if !errors.Is(getErr, errSecretNotFound) {
				return "", getErr
			}
			continue
		}
		if profileName, ok := decodeProfileName(baseCredentialKeyPrefix, key); ok {
			value, getErr := store.Get(key)
			if getErr != nil {
				return "", getErr
			}
			credential, decodeErr := decodeCredential(value, profileName)
			if decodeErr != nil {
				return "", decodeErr
			}
			plan[profileName] = credential
			continue
		}
		if profileName, ok := decodeProfileName(sessionCredentialPrefix, key); ok {
			value, getErr := store.Get(key)
			if getErr != nil {
				return "", getErr
			}
			credential, decodeErr := decodeCredential(value, profileName)
			if decodeErr != nil {
				return "", decodeErr
			}
			if credential.Expiration != nil && credential.Expiration.After(time.Now().UTC()) {
				credential.Name = profileName
				sessions = append(sessions, credential)
			}
		}
	}

	if len(plan) > 0 {
		if err := p.importLegacyCredentialPlan(plan); err != nil {
			return "", err
		}
	}
	for _, credential := range sessions {
		current, _, sessionErr := p.sessionCredentialForProfile(credential.Name)
		if sessionErr != nil {
			return "", sessionErr
		}
		if current != nil {
			continue
		}
		if err := p.storeSessionCredential(credential); err != nil {
			return "", err
		}
	}
	return selectedProfile, nil
}

func openLegacyStoreOnce(p *profile) (secretStore, error) {
	if p.legacyStoreLoaded {
		return nil, nil
	}
	p.legacyStoreLoaded = true
	if p.legacyStoreFactory == nil {
		return nil, nil
	}
	store, err := p.legacyStoreFactory()
	if err != nil {
		return nil, err
	}
	p.legacyStoreFactory = nil
	return store, nil
}

func (p *profile) syncConfig(selectedProfile string, profileNames []string) error {
	cfg, err := p.loadConfigFile()
	if err != nil {
		return err
	}
	defaultSection, created, err := ensureSection(cfg, Default)
	if err != nil {
		return err
	}
	changed := created

	if selectedProfile != "" {
		if hasCredentialSource(defaultSection) {
			return errors.New("default profile contains an unsupported role or external credential source; actool did not rewrite AWS config")
		}
		if hasStaticCredentials(defaultSection) {
			return errors.New("default profile contains static credentials in AWS config; actool did not rewrite AWS config")
		}
		if selectedProfile != Default {
			if selectedSection, sectionErr := cfg.GetSection(profileSectionName(selectedProfile)); sectionErr == nil {
				if hasCredentialSource(selectedSection) {
					return fmt.Errorf("selected profile %q contains an unsupported role or external credential source; actool did not rewrite AWS config", selectedProfile)
				}
				if hasStaticCredentials(selectedSection) {
					return fmt.Errorf("selected profile %q contains static credentials in AWS config; actool did not rewrite AWS config", selectedProfile)
				}
				existing := strings.TrimSpace(selectedSection.Key(CredentialProcess).String())
				if existing != "" && !p.isActoolCredentialProcess(existing) {
					return fmt.Errorf("selected profile %q already has a different credential_process; actool did not rewrite AWS config", selectedProfile)
				}
			}
		}
		existing := strings.TrimSpace(defaultSection.Key(CredentialProcess).String())
		if existing != "" && !p.isActoolCredentialProcess(existing) {
			return errors.New("default profile already has a different credential_process; remove it before selecting a profile with actool")
		}
		changed = ensureKey(defaultSection, CredentialProcess, p.credentialProcessCommand(selectedProfile)) || changed
		changed = p.copySelectedProfileConfig(cfg, defaultSection, selectedProfile) || changed
	}

	for _, profileName := range profileNames {
		if profileName == Default {
			continue
		}
		section, sectionCreated, sectionErr := ensureSection(cfg, profileSectionName(profileName))
		if sectionErr != nil {
			return sectionErr
		}
		changed = sectionCreated || changed
		if hasCredentialSource(section) {
			continue
		}
		if hasStaticCredentials(section) {
			continue
		}
		existing := strings.TrimSpace(section.Key(CredentialProcess).String())
		if existing != "" && !p.isActoolCredentialProcess(existing) {
			continue
		}
		changed = ensureKey(section, CredentialProcess, p.credentialProcessCommand(profileName)) || changed
	}

	if !changed {
		return nil
	}
	return saveConfigAtomic(p.configPath, cfg)
}

func (p *profile) copySelectedProfileConfig(cfg *ini.File, defaultSection *ini.Section, selectedProfile string) bool {
	sourceSection := defaultSection
	if selectedProfile != Default {
		if section, err := cfg.GetSection(profileSectionName(selectedProfile)); err == nil {
			sourceSection = section
		}
	}
	changed := false
	for _, keyName := range []string{Region, Output} {
		value := strings.TrimSpace(sourceSection.Key(keyName).String())
		if value != "" {
			changed = ensureKey(defaultSection, keyName, value) || changed
		}
	}
	return changed
}

func (p *profile) isActoolCredentialProcess(value string) bool {
	args, ok := splitCommandLine(strings.TrimSpace(value))
	if !ok || (len(args) != 2 && len(args) != 4) {
		return false
	}
	if args[1] != credentialProcessCommand {
		return false
	}
	if len(args) == 4 && args[2] != "--profile" {
		return false
	}
	commandName := args[0]
	if commandName == defaultCommandName || commandName == p.commandName {
		return true
	}
	return filepath.Base(p.commandName) == defaultCommandName && filepath.Base(commandName) == defaultCommandName
}

func hasCredentialSource(section *ini.Section) bool {
	for _, keyName := range []string{
		"role_arn",
		"source_profile",
		"credential_source",
		"web_identity_token_file",
		"web_identity_token_process",
		"sso_start_url",
		"sso_session",
		"sso_account_id",
		"sso_role_name",
	} {
		if strings.TrimSpace(section.Key(keyName).String()) != "" {
			return true
		}
	}
	return false
}

func hasStaticCredentials(section *ini.Section) bool {
	for _, keyName := range []string{AWSAccessKeyId, AWSSecretAccessKey, AWSSessionToken} {
		if strings.TrimSpace(section.Key(keyName).String()) != "" {
			return true
		}
	}
	return false
}

func (p *profile) loadConfigs() ([]*Config, error) {
	cfg, err := p.loadConfigFile()
	if err != nil {
		return nil, err
	}
	configs := make([]*Config, 0)
	for _, section := range cfg.Sections() {
		profileName, ok := configProfileName(section.Name())
		if !ok {
			continue
		}
		configs = append(configs, &Config{
			Name:              profileName,
			Region:            strings.TrimSpace(section.Key(Region).String()),
			Output:            strings.TrimSpace(section.Key(Output).String()),
			CredentialProcess: strings.TrimSpace(section.Key(CredentialProcess).String()),
		})
	}
	sort.Slice(configs, func(i, j int) bool {
		return configs[i].Name < configs[j].Name
	})
	return configs, nil
}

func (p *profile) loadConfigFile() (*ini.File, error) {
	options := ini.LoadOptions{
		Loose:                   true,
		PreserveSurroundedQuote: true,
	}
	cfg, err := ini.LoadSources(options, p.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ini.Empty(options), nil
		}
		return nil, err
	}
	return cfg, nil
}

func (p *profile) loadState() (profileState, error) {
	if p.state == nil {
		return profileState{}, errStateNotFound
	}
	return p.state.Load()
}

func (p *profile) saveState(state profileState) error {
	if p.state == nil {
		return errors.New("state store is nil")
	}
	state.Version = stateVersion
	return p.state.Save(state)
}

func (p *profile) removeSecret(key string) error {
	err := p.secrets.Remove(key)
	if errors.Is(err, errSecretNotFound) {
		return nil
	}
	return err
}

func (k *keyringStore) Get(key string) ([]byte, error) {
	item, err := k.keyring.Get(key)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return nil, errSecretNotFound
		}
		return nil, err
	}
	return append([]byte(nil), item.Data...), nil
}

func (k *keyringStore) Set(key string, value []byte) error {
	item := keyring.Item{
		Key:   key,
		Data:  append([]byte(nil), value...),
		Label: fmt.Sprintf("aws-vault (%s)", key),
	}
	if metadata, ok := parseSessionKey(key); ok {
		item.Label = fmt.Sprintf("aws-vault session for %s (expires %s)", metadata.ProfileName, metadata.Expiration.Format(time.RFC3339))
		item.Description = "aws-vault session"
	} else {
		// Match aws-vault's policy: master credentials require an explicit
		// keychain approval, while short-lived session credentials use the
		// trusted application setting for normal credential_process use.
		item.KeychainNotTrustApplication = true
	}
	return k.keyring.Set(item)
}

func (k *keyringStore) Remove(key string) error {
	err := k.keyring.Remove(key)
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return errSecretNotFound
	}
	return err
}

func (k *keyringStore) Keys() ([]string, error) {
	keys, err := k.keyring.Keys()
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return nil, errSecretNotFound
		}
		return nil, err
	}
	return keys, nil
}

func (f *fileStateStore) Load() (profileState, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return profileState{}, errStateNotFound
		}
		return profileState{}, err
	}
	var state profileState
	if err := json.Unmarshal(data, &state); err != nil {
		return profileState{}, err
	}
	if state.Version != 0 && state.Version != stateVersion {
		return profileState{}, fmt.Errorf("unsupported actool state version: %d", state.Version)
	}
	return state, nil
}

func (f *fileStateStore) Save(state profileState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(f.path, append(data, '\n'), 0o600)
}

func (m *memoryStateStore) Load() (profileState, error) {
	if !m.exists {
		return profileState{}, errStateNotFound
	}
	return m.state, nil
}

func (m *memoryStateStore) Save(state profileState) error {
	m.state = state
	m.exists = true
	return nil
}

func decodeCredential(data []byte, profileName string) (*Credential, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, err
	}

	accessKey := jsonString(values, "AccessKeyID", "AccessKeyId", "AccessKey", "access_key", "accessKey", AWSAccessKeyId)
	secretKey := jsonString(values, "SecretAccessKey", "SecretKey", "secret_key", "secretKey", AWSSecretAccessKey)
	sessionToken := jsonString(values, "SessionToken", "session_token", "sessionToken", AWSSessionToken)
	if strings.TrimSpace(accessKey) == "" || strings.TrimSpace(secretKey) == "" {
		return nil, fmt.Errorf("credential is incomplete. [%s]", profileName)
	}

	expiration, err := jsonTime(values, "Expiration", "expiration")
	if err != nil {
		return nil, err
	}
	if expiration == nil && jsonBool(values, "CanExpire") {
		expiration, err = jsonTime(values, "Expires")
		if err != nil {
			return nil, err
		}
		if expiration == nil {
			return nil, fmt.Errorf("expiring credential has no expiration. [%s]", profileName)
		}
	}
	return &Credential{
		Name:         profileName,
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		SessionToken: sessionToken,
		Expiration:   expiration,
	}, nil
}

func jsonString(values map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		raw, ok := values[name]
		if !ok {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil && value != "" {
			return value
		}
	}
	return ""
}

func jsonBool(values map[string]json.RawMessage, name string) bool {
	raw, ok := values[name]
	if !ok {
		return false
	}
	var value bool
	return json.Unmarshal(raw, &value) == nil && value
}

func jsonTime(values map[string]json.RawMessage, names ...string) (*time.Time, error) {
	for _, name := range names {
		raw, ok := values[name]
		if !ok {
			continue
		}
		var value time.Time
		if err := json.Unmarshal(raw, &value); err == nil {
			if !value.IsZero() {
				value = value.UTC()
				return &value, nil
			}
			continue
		}

		var timestamp float64
		if err := json.Unmarshal(raw, &timestamp); err == nil {
			value = time.Unix(int64(timestamp), 0).UTC()
			return &value, nil
		}

		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			parsed, parseErr := time.Parse(time.RFC3339Nano, text)
			if parseErr == nil {
				parsed = parsed.UTC()
				return &parsed, nil
			}
			return nil, parseErr
		}
		return nil, fmt.Errorf("invalid time value for %s", name)
	}
	return nil, nil
}

// storeCredential is retained for package-level callers from the previous
// implementation. New code should use storeSessionCredential or import plans.
func (p *profile) storeCredential(prefix, profileName string, credential *Credential) error {
	if credential == nil {
		return errors.New("credential is nil")
	}
	if prefix == baseCredentialKeyPrefix {
		if err := validateProfileName(profileName); err != nil {
			return err
		}
		data := map[string]interface{}{
			"AccessKeyID":     credential.AccessKey,
			"SecretAccessKey": credential.SecretKey,
			"SessionToken":    credential.SessionToken,
			"Source":          "",
			"CanExpire":       credential.Expiration != nil,
			"Expires":         time.Time{},
			"AccountID":       "",
		}
		if credential.Expiration != nil {
			data["Expires"] = credential.Expiration.UTC()
		}
		encoded, err := json.Marshal(data)
		if err != nil {
			return err
		}
		return p.secrets.Set(profileName, encoded)
	}
	if prefix == sessionCredentialPrefix {
		credential.Name = profileName
		return p.storeSessionCredential(credential)
	}
	return fmt.Errorf("unsupported credential prefix: %s", prefix)
}

func credentialsEqual(left, right *Credential) bool {
	if left == nil || right == nil {
		return false
	}
	if left.AccessKey != right.AccessKey ||
		left.SecretKey != right.SecretKey ||
		left.SessionToken != right.SessionToken {
		return false
	}
	if left.Expiration == nil || right.Expiration == nil {
		return left.Expiration == nil && right.Expiration == nil
	}
	return left.Expiration.UTC().Equal(right.Expiration.UTC())
}

func parseLegacyCredentials(data []byte) (map[string]*Credential, string, error) {
	cfg, err := ini.LoadSources(ini.LoadOptions{PreserveSurroundedQuote: true}, data)
	if err != nil {
		return nil, "", err
	}

	plan := make(map[string]*Credential)
	named := make(map[string]*Credential)
	for _, section := range cfg.Sections() {
		name := section.Name()
		if name == ini.DefaultSection || name == Default {
			continue
		}
		if err := validateProfileName(name); err != nil {
			return nil, "", err
		}
		credential, ok, err := credentialFromSection(section, false)
		if err != nil {
			return nil, "", err
		}
		if !ok {
			continue
		}
		credential.Name = name
		named[name] = credential
		plan[name] = credential
	}

	suggestedProfile := ""
	if section, sectionErr := cfg.GetSection(Default); sectionErr == nil {
		actual, hasActual, err := credentialFromSection(section, false)
		if err != nil {
			return nil, "", err
		}
		original, hasOriginal, err := credentialFromSection(section, true)
		if err != nil {
			return nil, "", err
		}

		base := actual
		if hasOriginal {
			base = original
		}
		if hasActual {
			suggestedProfile = matchingProfileIgnoringSession(actual, named)
		}
		if base != nil {
			base.Name = Default
			plan[Default] = base
		}
		if suggestedProfile == "" && base != nil {
			suggestedProfile = Default
		}
	}
	return plan, suggestedProfile, nil
}

func credentialFromSection(section *ini.Section, useOriginal bool) (*Credential, bool, error) {
	accessKeyName := AWSAccessKeyId
	secretKeyName := AWSSecretAccessKey
	if useOriginal {
		accessKeyName = OriginalAWSAccessKeyId
		secretKeyName = OriginalAWSSecretAccessKey
	}

	accessKey := strings.TrimSpace(section.Key(accessKeyName).String())
	secretKey := strings.TrimSpace(section.Key(secretKeyName).String())
	if accessKey == "" && secretKey == "" {
		if !useOriginal && strings.TrimSpace(section.Key(AWSSessionToken).String()) != "" {
			return nil, false, fmt.Errorf("profile %q contains a session token without access keys", section.Name())
		}
		return nil, false, nil
	}
	if accessKey == "" || secretKey == "" {
		return nil, false, fmt.Errorf("profile %q contains an incomplete credential", section.Name())
	}

	credential := &Credential{AccessKey: accessKey, SecretKey: secretKey}
	if !useOriginal {
		credential.SessionToken = strings.TrimSpace(section.Key(AWSSessionToken).String())
	}
	return credential, true, nil
}

func matchingProfileIgnoringSession(target *Credential, named map[string]*Credential) string {
	if target == nil {
		return ""
	}
	names := make([]string, 0, len(named))
	for name := range named {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		candidate := named[name]
		if candidate != nil && candidate.AccessKey == target.AccessKey && candidate.SecretKey == target.SecretKey {
			return name
		}
	}
	return ""
}

func fingerprintLegacyCredentials(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func sessionKey(metadata sessionMetadata) string {
	return strings.Join([]string{
		metadata.Type,
		base64.RawURLEncoding.EncodeToString([]byte(metadata.ProfileName)),
		base64.RawURLEncoding.EncodeToString([]byte(metadata.MFASerial)),
		strconv.FormatInt(metadata.Expiration.Unix(), 10),
	}, ",")
}

func parseSessionKey(key string) (sessionMetadata, bool) {
	parts := strings.Split(key, ",")
	if len(parts) == 4 && parts[0] != "" && parts[0] != "session" {
		profileBytes, profileErr := base64.RawURLEncoding.DecodeString(parts[1])
		mfaBytes, mfaErr := base64.RawURLEncoding.DecodeString(parts[2])
		expiration, expirationErr := strconv.ParseInt(parts[3], 10, 64)
		if profileErr == nil && mfaErr == nil && expirationErr == nil {
			return sessionMetadata{
				Type:        parts[0],
				ProfileName: string(profileBytes),
				MFASerial:   string(mfaBytes),
				Expiration:  time.Unix(expiration, 0).UTC(),
			}, true
		}
	}
	if strings.HasPrefix(key, "session,") {
		legacyParts := strings.Split(key, ",")
		if len(legacyParts) == 4 {
			expiration, err := strconv.ParseInt(legacyParts[3], 10, 64)
			if err == nil {
				return sessionMetadata{Type: sessionTypeGetSession, ProfileName: legacyParts[1], MFASerial: legacyParts[2], Expiration: time.Unix(expiration, 0).UTC()}, true
			}
		}
	}
	if strings.HasPrefix(key, "session:") {
		legacyBody := strings.TrimPrefix(key, "session:")
		expirationSeparator := strings.LastIndex(legacyBody, ":")
		profileSeparator := strings.Index(legacyBody, ":")
		if expirationSeparator > profileSeparator && profileSeparator > 0 {
			expiration, err := strconv.ParseInt(legacyBody[expirationSeparator+1:], 10, 64)
			if err == nil {
				return sessionMetadata{
					Type:        sessionTypeGetSession,
					ProfileName: legacyBody[:profileSeparator],
					MFASerial:   legacyBody[profileSeparator+1 : expirationSeparator],
					Expiration:  time.Unix(expiration, 0).UTC(),
				}, true
			}
		}
	}
	if end := strings.LastIndex(key, " session ("); end > 0 && strings.HasSuffix(key, ")") {
		expirationText := strings.TrimSuffix(key[end+len(" session ("):], ")")
		expiration, err := strconv.ParseInt(expirationText, 10, 64)
		if err == nil {
			return sessionMetadata{Type: sessionTypeGetSession, ProfileName: key[:end], Expiration: time.Unix(expiration, 0).UTC()}, true
		}
	}
	return sessionMetadata{}, false
}

func isNonProfileKey(key string) bool {
	if key == selectedProfileKey || key == legacyCredentialsHashKey || key == "selected_profile" || key == "selectedProfile" {
		return true
	}
	if strings.HasPrefix(key, "oidc:") || strings.HasPrefix(key, "credential/") {
		return true
	}
	_, isSession := parseSessionKey(key)
	return isSession
}

func defaultSelectedProfile(profileNames []string) string {
	for _, profileName := range profileNames {
		if profileName == Default {
			return Default
		}
	}
	if len(profileNames) == 0 {
		return ""
	}
	return profileNames[0]
}

func sortProfileNames(profileNames []string) {
	sort.Slice(profileNames, func(i, j int) bool {
		if profileNames[i] == Default && profileNames[j] == Default {
			return false
		}
		if profileNames[i] == Default {
			return true
		}
		if profileNames[j] == Default {
			return false
		}
		return profileNames[i] < profileNames[j]
	})
}

func containsProfile(profileNames []string, selectedProfile string) bool {
	for _, profileName := range profileNames {
		if profileName == selectedProfile {
			return true
		}
	}
	return false
}

func validateProfileName(profileName string) error {
	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return errors.New("profile name is empty")
	}
	if strings.ContainsAny(profileName, "\x00\r\n") {
		return fmt.Errorf("profile name contains a control character: %q", profileName)
	}
	if strings.ContainsAny(profileName, "[]") {
		return fmt.Errorf("profile name contains an INI section delimiter: %q", profileName)
	}
	if profileName == selectedProfileKey || profileName == legacyCredentialsHashKey || profileName == "selected_profile" || profileName == "selectedProfile" || strings.HasPrefix(profileName, "credential/") || strings.HasPrefix(profileName, "oidc:") {
		return fmt.Errorf("profile name is reserved for secure-store metadata: %q", profileName)
	}
	if _, ok := parseSessionKey(profileName); ok {
		return fmt.Errorf("profile name is reserved for a session credential: %q", profileName)
	}
	return nil
}

func profileSectionName(profileName string) string {
	if profileName == Default {
		return Default
	}
	return "profile " + profileName
}

func configProfileName(sectionName string) (string, bool) {
	if sectionName == Default {
		return Default, true
	}
	if strings.HasPrefix(sectionName, "profile ") {
		profileName := strings.TrimPrefix(sectionName, "profile ")
		if validateProfileName(profileName) == nil {
			return profileName, true
		}
	}
	return "", false
}

func ensureSection(cfg *ini.File, name string) (*ini.Section, bool, error) {
	section, err := cfg.GetSection(name)
	if err == nil {
		return section, false, nil
	}
	section, err = cfg.NewSection(name)
	if err != nil {
		return nil, false, err
	}
	return section, true, nil
}

func ensureKey(section *ini.Section, key, value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	if !section.HasKey(key) {
		_, _ = section.NewKey(key, value)
		return true
	}
	if section.Key(key).String() == value {
		return false
	}
	section.Key(key).SetValue(value)
	return true
}

func secretKey(prefix, profileName string) string {
	return prefix + base64.RawURLEncoding.EncodeToString([]byte(profileName))
}

func decodeProfileName(prefix, key string) (string, bool) {
	if !strings.HasPrefix(key, prefix) {
		return "", false
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, prefix))
	if err != nil {
		return "", false
	}
	profileName := string(data)
	if validateProfileName(profileName) != nil {
		return "", false
	}
	return profileName, true
}

func awsProfilePaths(homeDir string) (string, string) {
	configPath := os.Getenv("AWS_CONFIG_FILE")
	if configPath == "" {
		configPath = filepath.Join(homeDir, ".aws", "config")
	}
	credentialsPath := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if credentialsPath == "" {
		credentialsPath = filepath.Join(homeDir, ".aws", "credentials")
	}
	return configPath, credentialsPath
}

func defaultStatePath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		homeDir, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return filepath.Join(".actool", "state.json")
		}
		configDir = homeDir
	}
	return filepath.Join(configDir, "actool", "state.json")
}

func executableCommandName() string {
	executable, err := os.Executable()
	if err != nil {
		return defaultCommandName
	}
	absolute, err := filepath.Abs(executable)
	if err != nil {
		return executable
	}
	return absolute
}

func splitCommandLine(command string) ([]string, bool) {
	if runtime.GOOS == "windows" {
		return splitWindowsCommandLine(command)
	}
	return splitPosixCommandLine(command)
}

func splitPosixCommandLine(command string) ([]string, bool) {
	var args []string
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false
	escaped := false
	started := false

	flush := func() {
		if started {
			args = append(args, current.String())
			current.Reset()
			started = false
		}
	}

	for _, character := range command {
		if escaped {
			current.WriteRune(character)
			escaped = false
			started = true
			continue
		}
		if inSingleQuote {
			if character == '\'' {
				inSingleQuote = false
			} else {
				current.WriteRune(character)
			}
			started = true
			continue
		}
		if inDoubleQuote {
			switch character {
			case '"':
				inDoubleQuote = false
			case '\\', '$', '`':
				escaped = true
			default:
				current.WriteRune(character)
			}
			started = true
			continue
		}

		switch character {
		case '\'', '"':
			started = true
			if character == '\'' {
				inSingleQuote = true
			} else {
				inDoubleQuote = true
			}
		case '\\':
			escaped = true
			started = true
		case ' ', '\t', '\r', '\n':
			flush()
		default:
			current.WriteRune(character)
			started = true
		}
	}

	if escaped || inSingleQuote || inDoubleQuote {
		return nil, false
	}
	flush()
	return args, true
}

func splitWindowsCommandLine(command string) ([]string, bool) {
	var args []string
	var current strings.Builder
	inQuotes := false
	backslashes := 0
	started := false

	flush := func() {
		if started {
			args = append(args, current.String())
			current.Reset()
			started = false
		}
	}

	for _, character := range command {
		switch character {
		case '\\':
			backslashes++
		case '"':
			current.WriteString(strings.Repeat("\\", backslashes/2))
			if backslashes%2 == 1 {
				current.WriteByte('"')
			} else {
				inQuotes = !inQuotes
			}
			backslashes = 0
			started = true
		case ' ', '\t':
			current.WriteString(strings.Repeat("\\", backslashes))
			backslashes = 0
			if inQuotes {
				current.WriteRune(character)
				started = true
			} else {
				flush()
			}
		default:
			current.WriteString(strings.Repeat("\\", backslashes))
			backslashes = 0
			current.WriteRune(character)
			started = true
		}
	}
	current.WriteString(strings.Repeat("\\", backslashes))
	if inQuotes {
		return nil, false
	}
	flush()
	return args, true
}

func quoteCommandArg(argument string) string {
	if runtime.GOOS == "windows" {
		return quoteWindowsCommandArg(argument)
	}
	return quotePosixCommandArg(argument)
}

func quotePosixCommandArg(argument string) string {
	if argument != "" && strings.IndexFunc(argument, func(r rune) bool { return !isSafePosixCommandRune(r) }) == -1 {
		return argument
	}
	return "'" + strings.ReplaceAll(argument, "'", "'\\''") + "'"
}

func isSafePosixCommandRune(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		strings.ContainsRune("_@%+=:,./-", r)
}

func quoteWindowsCommandArg(argument string) string {
	if argument != "" && strings.IndexFunc(argument, func(r rune) bool { return !isSafeWindowsCommandRune(r) }) == -1 {
		return argument
	}
	var builder strings.Builder
	builder.WriteByte('"')
	backslashes := 0
	for _, character := range argument {
		switch character {
		case '\\':
			backslashes++
		case '"':
			builder.WriteString(strings.Repeat("\\", backslashes*2+1))
			builder.WriteByte('"')
			backslashes = 0
		default:
			builder.WriteString(strings.Repeat("\\", backslashes))
			builder.WriteRune(character)
			backslashes = 0
		}
	}
	builder.WriteString(strings.Repeat("\\", backslashes*2))
	builder.WriteByte('"')
	return builder.String()
}

func isSafeWindowsCommandRune(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		strings.ContainsRune("_@%+=:,./-\\", r)
}

func (p *profile) credentialProcessCommand(profileName string) string {
	args := []string{p.commandName, credentialProcessCommand}
	if profileName != "" {
		args = append(args, "--profile", profileName)
	}
	quoted := make([]string, 0, len(args))
	for _, argument := range args {
		quoted = append(quoted, quoteCommandArg(argument))
	}
	return strings.Join(quoted, " ")
}

func saveConfigAtomic(path string, cfg *ini.File) error {
	var buffer bytes.Buffer
	if _, err := cfg.WriteTo(&buffer); err != nil {
		return err
	}
	return writeFileAtomic(path, buffer.Bytes(), 0o600)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := temp.Chmod(mode.Perm()); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return nil
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func backupLegacyCredentials(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	baseBackupPath := path + ".actool-backup"
	for suffix := 0; suffix < 100; suffix++ {
		backupPath := baseBackupPath
		if suffix > 0 {
			backupPath = fmt.Sprintf("%s-%d", baseBackupPath, suffix)
		}
		if _, err := os.Lstat(backupPath); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(path, backupPath); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("could not create a unique legacy credentials backup beside %s", path)
}

var _ Profile = (*profile)(nil)
