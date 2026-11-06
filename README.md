# Password Security Suite (PSS)

**A local-first password toolkit and encrypted password vault.**

PSS provides password generation, passphrase generation, offline password-strength analysis, and an optional encrypted local vault. It includes a command-line interface (CLI) and a local Flask GUI.

## Project status

**Status:** Pre-release published (`v1.0.0-rc.1`)

- Four automated tests passed in the developer's Windows environment.
- Independent security review has not been completed.
- Do not treat this project as a professionally audited password manager or store production credentials until the required security reviews are complete.

## Features

- Cryptographically secure password generation using Python `secrets`.
- Passphrase generation.
- Offline password-strength analysis using zxcvbn.
- Local SQLite vault.
- AES-256-GCM authenticated encryption.
- Argon2id key derivation.
- CLI and local Flask GUI.
- No cloud account, telemetry, remote database, or external password-checking API in core operation.

## Requirements

- Windows 10/11 or a compatible Python environment.
- Python 3.12 recommended.
- pip.

## Installation — Windows

```powershell
git clone https://github.com/shaikhumaid1/Password-security-suite.git
cd Password-security-suite

py -m venv .venv
.venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation, use the Python executable directly:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe app.py
```

## Run the GUI

```powershell
python app.py
```

Open http://127.0.0.1:5000 in your browser.

The application is intended for local use. Keep the server bound to loopback; do not change it to `0.0.0.0`, expose it through port forwarding, or make it reachable from an untrusted network.

## CLI commands

```powershell
python cli.py generate --length 24
python cli.py passphrase
python cli.py analyze
python cli.py vault-create
python cli.py vault-add
python cli.py vault-list
python cli.py vault-delete
```

CLI password prompts use hidden input. Do not pass passwords as command-line arguments.

## Data storage and privacy

The vault database is stored locally under:

`instance/vault.db`

The `instance` directory is excluded from Git. Never publish vault databases, master passwords, encryption keys, recovery material, or private backups.

The repository is public source code; that does not mean local vault data is uploaded to GitHub. Protect local backups separately.

## Security architecture

- Argon2id derives a key-encryption key from the master password.
- A random data-encryption key protects vault entries.
- AES-256-GCM provides authenticated encryption.
- Each encryption operation uses a fresh random nonce.
- SQLite stores encrypted credential payloads.

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md).

## Testing

Run the automated test suite:

```powershell
python -m pytest -v
```

The current local baseline is **4 passing tests** in the developer's Windows environment. This is a small test suite and does not establish overall application security.

## Security limitations

PSS has not undergone an independent professional security audit. Local processing cannot protect against malware, keyloggers, a compromised operating system, malicious browser extensions, physical access to an unlocked device, insecure backups, or memory inspection while the vault is unlocked. Python does not guarantee secure zeroization of all secrets in memory.

The previous v1 account/MFA database is not automatically migrated into the new vault. Preserve existing data and backups until a migration process has been designed and verified. See [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## License

This project is licensed under the [MIT License](LICENSE) (Copyright © 2026 umaid shaikh). You may use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, subject to the conditions in the license. The copyright and permission notices must be included in copies or substantial portions of the software.
