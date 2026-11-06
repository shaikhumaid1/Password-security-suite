# Security Policy

## Project status

Password Security Suite (PSS) is a local-first project with a published pre-release (`v1.0.0-rc.1`). It has not received an independent professional security audit and must not be considered a production-certified password manager.

## Reporting a vulnerability

Please report suspected security vulnerabilities privately through the repository maintainer's GitHub contact/profile rather than publishing exploit details in a public issue.

Include:
- The affected component and version or commit.
- Reproduction steps and relevant environment details.
- The potential security impact.
- A proposed mitigation, if known.

Do not include real passwords, master passwords, private vault databases, recovery codes, or encryption keys in a report. Use synthetic test data.

Repository: https://github.com/shaikhumaid1/Password-security-suite

## Sensitive data

Never submit or publish:
- Master passwords or account credentials.
- Encryption keys or recovery material.
- Unredacted vault databases.
- Private backups or session secrets.

## Security boundaries

PSS aims to protect locally stored vault data using authenticated encryption and password-based key derivation. It cannot guarantee protection against malware, keyloggers, compromised operating systems, memory inspection, malicious browser extensions, physical access to an unlocked device, or insecure backups.

Keep the application bound to localhost. Do not expose the development server to public or untrusted networks.

## Supported versions

During this pre-release stage, security fixes are applied to the current development branch. A formal supported-version policy will be established when stable releases are published.
