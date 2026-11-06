# Release readiness checklist

This checklist tracks the work required before publishing a stable release of Password Security Suite (PSS).

## Verified in the developer environment

- [x] Windows installation script completes successfully.
- [x] Windows launcher starts the local Flask GUI.
- [x] GUI vault setup, unlock, add, reveal, and delete workflows were manually exercised.
- [x] CLI password generation, passphrase generation, and password analysis were manually exercised.
- [x] Automated test baseline: 4 tests passed on Windows with Python 3.12.4.
- [x] Git repository is clean and synchronized with origin/main at the time of verification.
- [x] Local runtime data and virtual environments are excluded from Git.

## Required before a stable public release

- [ ] Run the full test suite on a clean Windows installation, not only the developer's existing environment.
- [ ] Add tests for GUI routes, CSRF enforcement, vault idle timeout, malformed input, and error handling.
- [ ] Review vault key lifecycle, session handling, authentication throttling, and memory exposure.
- [ ] Verify encrypted database contents do not contain plaintext credentials or notes.
- [ ] Perform dependency vulnerability and license review; pin or lock release dependencies.
- [ ] Perform independent cryptographic and application security review.
- [ ] Verify backup and restore procedures, including recovery from a corrupted database.
- [ ] Decide and add an explicit software license.
- [ ] Build and test a distributable package on a clean machine.
- [ ] Review documentation, screenshots, and release notes for accuracy.

## Packaging rules

Never include any of the following in a source archive or installer:

- `.venv/` or `venv/`
- `instance/` or any SQLite database
- Flask secret key files
- `.env` files, logs, caches, or test artifacts
- Real credentials, recovery material, or private backups

The source archive should contain application source, templates, static assets, scripts, tests, documentation, and dependency declarations only.

## Release decision

Until all required security and clean-install checks are complete, publish only a clearly labelled pre-release for evaluation with synthetic test data. Do not describe PSS as audited, production-certified, or equivalent to an established password manager.
