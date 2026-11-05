# Password Security Suite

A local-first Flask learning project for password generation, password-strength analysis, and account security controls.

## Features

- Cryptographically secure password generation with Python `secrets`.
- Configurable length (8–128), character classes, and ambiguous-character exclusion.
- Password-strength estimation with `zxcvbn`; submitted passwords are not stored by the checker.
- Master-password hashing with Werkzeug's scrypt password hashing.
- TOTP multi-factor authentication (MFA) using `pyotp` and QR-code enrollment.
- Eight single-use recovery codes; only password hashes are stored.
- Recovery-code-based master-password reset, with recovery-code rotation after reset.
- Last-resort destructive local-account reset when both master password and recovery codes are lost.
- Security settings page to change the master password and regenerate recovery codes after re-authentication with the current password and TOTP.
- SQLite persistence, HTTP security headers, no-store responses, and a 15-minute permanent-session lifetime.
- Local-only server binding at `127.0.0.1:5000`.

## Presentation demo (shareable, no credentials)

A static interactive preview is available at `demo/index.html`. It is designed for presentations and does not authenticate users, create accounts, validate MFA, send data to a server, or persist entered values. Its sample password generator is illustrative only and does not use cryptographically secure randomness. Do not enter real passwords.

### Publish the static demo with GitHub Pages

1. Open the repository on GitHub.
2. Go to **Settings → Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**.
4. Select branch **main** and folder **/ (root)**, then save.
5. Once GitHub Pages finishes publishing, the demo URL will be:
   `https://shaikhumaid1.github.io/Password-security-suite/demo/`

If the page is not available immediately, wait for the Pages deployment to finish and check the **Actions** tab.

### Two ways to present

- **In-person real application:** run `python app.py` on your laptop and open `http://127.0.0.1:5000`. This uses your local SQLite account and MFA configuration.
- **Shareable online preview:** share the GitHub Pages demo URL. It is a frontend-only simulation and is not connected to your local database or authentication.

Do not deploy the current Flask authentication application publicly. It is a local educational app, not production-hardened. For remote live demonstrations, use a separate staging environment with dummy data, HTTPS, proper CSRF protection, rate limiting, secure cookie settings, and a security review.

## Requirements

- Python 3.10+
- Windows, macOS, or Linux

## Run on Windows 11

```powershell
py -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

If PowerShell blocks activation for this terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\\.venv\\Scripts\\Activate.ps1
```

Open http://127.0.0.1:5000.

## Run on macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

## First-time setup

1. Create a username and a unique master password (minimum 12 characters).
2. Enroll an authenticator app by scanning the QR code.
3. Verify the six-digit TOTP code.
4. Save the eight recovery codes offline. They are displayed only when generated.
5. Sign in using the master password and authenticator code.

## Account recovery

- If the master password is forgotten but a recovery code remains, use **Forgot master password?** on the login page. The recovery-code set is rotated after a successful reset.
- If signed in, open **Security settings** to change the master password or regenerate recovery codes. Both actions require the current master password and a valid TOTP code.
- If both the master password and every recovery code are lost, use **Lost your master password and all recovery codes?** on the login page. This permanently deletes the local account row and returns to first-time setup. It does not recover old credentials or data.

## Security and limitations

- This is an educational local application, **not a professionally audited password manager**. Do not use it to store production credentials or as your only MFA mechanism.
- It binds only to loopback. Do not expose the Flask development server to the internet or an untrusted network.
- Keep the `instance/` directory private. It contains the SQLite database and the app's signing key. It is excluded from Git.
- Back up the `instance/` directory securely if you need to preserve your local account. Losing the signing key invalidates existing browser sessions.
- The last-resort account reset is intentionally destructive. Because it is designed for the case where all credentials are lost, it cannot cryptographically verify account ownership; anyone with local access to the app can initiate it.
- This version does not provide encrypted password-vault storage, email recovery, multi-user accounts, production-grade CSRF protection, or a professionally audited threat model. Keep it local and use it for learning/demo purposes.

## Project structure

```text
Password-security-suite/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── templates/
│   ├── base.html
│   ├── setup.html
│   ├── login.html
│   ├── mfa_enroll.html
│   ├── forgot_password.html
│   ├── reset_account.html
│   ├── recovery.html
│   ├── security.html
│   └── index.html
├── static/
│   └── style.css
└── instance/                 # created at runtime; never commit
```

## Learning outcomes

Python web development, cryptographically secure randomness, password hashing, TOTP MFA, recovery-factor lifecycle, SQLite, session handling, HTTP security headers, and secure-by-default local application design.
