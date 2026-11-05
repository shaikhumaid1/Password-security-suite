# Password Security Suite

**Local-first password toolkit + optional encrypted password vault.** Public source code; private user data. The application is designed to process credentials on the user's own computer and does not require a cloud account or remote password service.

> Security status: v2 foundation committed. The integrated application has not yet completed its test and independent security-review phase. Do not store production credentials until those reviews are complete.

## Features
- Cryptographically secure password and passphrase generation using Python secrets.
- Offline password-strength analysis using zxcvbn; analyzer input is not saved.
- Optional local SQLite vault with AES-256-GCM authenticated encryption.
- Argon2id key derivation and random vault data-encryption key.
- CLI and local Flask GUI.
- No telemetry, cloud sync, remote database, or external password-checking API in core operation.

## Windows installation

    git clone https://github.com/shaikhumaid1/Password-security-suite.git
    cd Password-security-suite
    py -m venv .venv
    .venv\\Scripts\\Activate.ps1
    python -m pip install -r requirements.txt

## Run GUI

    python app.py

Open http://127.0.0.1:5000. The server binds to loopback. Do not change it to 0.0.0.0 or expose it through port forwarding.

## CLI

    python cli.py generate --length 24
    python cli.py passphrase
    python cli.py analyze
    python cli.py vault-create
    python cli.py vault-add
    python cli.py vault-list
    python cli.py vault-delete

CLI password prompts use hidden input. Do not pass passwords as command-line arguments.

## Data and privacy
The vault database is stored under instance/vault.db and excluded from Git. Never upload the instance folder, database, backups, master passwords, recovery material, or encryption keys to a public repository. Public source code does not send user data to GitHub.

## Security design
The vault uses a random data key, wrapped by an Argon2id-derived key-encryption key. Credential records are encrypted with AES-256-GCM using a fresh random nonce per encryption and record ID as authenticated associated data. SQLite contains encrypted record payloads. KDF parameters are stored with vault metadata.

## Important limitations
This is not yet a professionally audited password manager. Local processing cannot protect against malware, keyloggers, compromised devices, malicious browser extensions, or an unattended unlocked vault. Python does not guarantee secure zeroization of all secrets in memory. Backups must be protected separately. Review docs/threat-model.md. Existing v1 account/MFA data in instance/password_suite.db is not migrated into the new vault; keep a backup before upgrading. The previous account/MFA routes are replaced by the v2 vault interface, so do not delete your old data until migration is designed and verified.

## Testing (run after implementation review)

    python -m pytest

A successful local test run is not a substitute for cryptographic review, dependency review, penetration testing, or independent audit.
