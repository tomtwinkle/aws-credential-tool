# AWS Credential Tool - Secure Profile Switcher

`actool` keeps the existing interactive profile-switching workflow while moving
AWS credentials out of `~/.aws/credentials`. Credentials are stored using the
same `aws-vault` keyring namespace and JSON shapes, and AWS CLI reads them via
`credential_process`.

## What changes

- The interactive commands and profile choices remain the same.
- Long-lived credentials are stored under the `aws-vault` keyring service.
- STS session credentials use the `aws-vault` session-key format.
- `~/.aws/config` is updated atomically; unrelated role, SSO, and external
  `credential_process` profiles are preserved.
- `actool credential-process` is read-only. It never imports files, rewrites
  configuration, or deletes credentials.
- An expired session is never silently replaced with long-lived credentials.

The default backend prefers an available OS credential store (Keychain on
macOS, Windows Credential Manager, or a desktop Linux keyring). If no native
keyring is available, it uses aws-vault's encrypted file backend and prompts
for a non-empty passphrase. The `pass` backend is never selected implicitly;
it can be selected explicitly with `AWS_VAULT_BACKEND=pass`.

## First run and migration

1. Define profiles as before:

   ```console
   $ aws configure --profile "AWS Account Dev"
   $ aws configure --profile "AWS Account Stage"
   $ aws configure --profile "AWS Account Prod"
   ```

2. Run `actool`.

   `~/.aws/credentials` is imported into the secure store. The first
   interactive run asks whether the plaintext file should be deleted or kept as
   a manual-cleanup backup (for example, `credentials.actool-backup`). The
   source path is removed in either case so AWS CLI cannot prefer plaintext
   credentials. Deletion or backup occurs only
   after secure import succeeds; AWS config synchronization runs only after
   the plaintext source has been removed from the path AWS CLI reads.

3. Select a profile and choose the same action as before.

If the file is kept, it is not re-imported or prompted again until its
credentials change. Run `actool` after changing credentials with
`aws configure`; the changed entries are imported and the cleanup choice is
shown again.

Older `actool` secure-store entries are migrated automatically on the first
interactive run. Existing `aws-vault` entries are never overwritten by that
migration; conflicting names are reported so they can be resolved explicitly.

The migration honors `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`, so a
non-default AWS configuration can be migrated without copying files.

## Normal usage

```console
$ actool

# Use the arrow keys to navigate: ↑ ↓
# Select Profile:
    default
  > AWS Account Dev
    AWS Account Stage
    AWS Account Prod
```

The actions remain:

- `Set choose profile.` selects the profile used by the default AWS CLI
  configuration.
- `Set choose sessionToken.` prompts for the MFA token, obtains an STS session,
  and stores it in the secure store.

Normal AWS CLI commands continue to work:

```console
$ aws sts get-caller-identity
$ aws --profile "AWS Account Dev" s3 ls
```

## Generated configuration

The command is written as an absolute path in the real file. The following is
representative:

```ini
[default]
region = us-west-2
output = yaml
credential_process = /path/to/actool credential-process --profile 'AWS Account Dev'

[profile AWS Account Dev]
region = us-west-2
output = yaml
credential_process = /path/to/actool credential-process --profile 'AWS Account Dev'
```

`credential_process` output follows the AWS CLI external credential-process
contract (`Version`, `AccessKeyId`, `SecretAccessKey`, optional `SessionToken`,
and optional `Expiration`).

## Backend options

To force the encrypted file backend, or to select `pass`, set one of these
before running `actool`:

```console
$ export AWS_VAULT_BACKEND=file
$ export AWS_VAULT_FILE_PASSPHRASE='use-a-secret-manager-or-prompt'
```

Useful compatibility settings include:

- `AWS_VAULT_BACKEND`: `keychain`, `wincred`, `secret-service`, `kwallet`,
  `keyctl`, `file`, or `pass`, subject to the current platform.
- `AWS_VAULT_FILE_DIR`: encrypted-file keyring directory; defaults to
  `~/.awsvault/keys/`.
- `AWS_VAULT_FILE_PASSPHRASE`: optional non-interactive file-keyring
  passphrase. Prefer the terminal prompt or an external secret manager.
- `AWS_VAULT_KEYCHAIN_NAME` and
  `AWS_VAULT_SECRET_SERVICE_COLLECTION_NAME`: standard `aws-vault`
  compatibility settings.
- `AWS_VAULT_PASS_PASSWORD_STORE_DIR`, `AWS_VAULT_PASS_CMD`, and
  `AWS_VAULT_PASS_PREFIX`: standard `aws-vault` `pass` backend settings.

Do not put long-lived secrets in shell history, CI logs, or
`AWS_VAULT_FILE_PASSPHRASE` configuration that is readable by other users.

## Troubleshooting

- `no keyring backend available`: configure the OS keyring, or explicitly opt
  into an available `file`/`pass` backend as described above.
- `different credential_process`: the profile already belongs to another
  credential provider. Remove or deliberately change that provider before
  selecting it in `actool`.
- expired session credentials: run `actool` and choose
  `Set choose sessionToken.` again.

For the AWS external-process contract, see the [AWS CLI configuration
documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).
For the compatible keyring behavior, see the [aws-vault
repository](https://github.com/99designs/aws-vault).
