# Password Security Suite

A local Flask application for password generation, password-strength analysis, and time-based one-time password (TOTP) multi-factor authentication (MFA).

## Features
- Cryptographically secure password generation using Python `secrets`.
- Configurable password length and character sets, with optional ambiguous-character exclusion.
- Password-strength estimation using `zxcvbn`.
- Master-password hashing with Werkzeug's scrypt-based password hashing.
- TOTP-based MFA enrollment and login using `pyotp` and QR codes.
- Eight single-use recovery codes stored as hashes.
- SQLite storage for local account data.

## Requirements
- Python 3.10+
- Windows, macOS, or Linux

## Run on Windows 11

```powershell
# Extract the project and open PowerShell in its folder
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in your browser.

## Run on macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

## Security notes
- The app binds to `127.0.0.1` and is intended for local learning and demonstration. Do not expose it directly to the internet or an untrusted network.
- This project is not a professionally audited password manager. Do not use it to store real production credentials or your only MFA factor.
- Keep the `instance/` directory private; it contains the local SQLite database and runtime state. It is excluded from Git by `.gitignore`.
- Use a unique, strong master password. Keep recovery codes somewhere secure and offline.

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
│   ├── recovery.html
│   └── index.html
└── static/
    └── style.css
```

## Learning outcomes
This project demonstrates Python web development, secure random generation, password hashing, TOTP MFA, recovery-code handling, SQLite persistence, and basic application-security practices.
