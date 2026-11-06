# Changelog

Notable project changes are documented here.

## Unreleased — release preparation

### Added
- Local password and passphrase generation.
- Offline password-strength analysis.
- Encrypted SQLite password vault.
- Argon2id-based key derivation.
- AES-256-GCM authenticated encryption.
- Command-line interface.
- Local Flask graphical interface.
- Architecture and threat-model documentation.
- Initial automated tests.

### Security and privacy
- Local vault data is stored under the ignored `instance/` directory.
- The GUI is intended to bind to localhost.
- Security limitations and responsible disclosure guidance are documented.

### Known limitations
- No independent security audit has been completed.
- The previous v1 account/MFA database has no verified migration path to the v2 vault.
- Windows executable packaging and clean-machine installation testing remain pending.
- The current automated test suite is limited and is not a substitute for security testing.
