# Architecture

Password Security Suite is a local-first modular monolith. Flask GUI and CLI share Python core services. No cloud API, telemetry, remote database, or external password-checking API is part of core operation.

- pss/core: password generation, passphrases and strength analysis.
- pss/security: Argon2id key derivation and AES-256-GCM authenticated encryption.
- pss/vault: local SQLite vault repository.
- app.py: loopback-only Flask GUI.
- cli.py: terminal interface.

A random 256-bit data key encrypts individual JSON records with AES-256-GCM. The master password is processed with Argon2id to derive a key-encryption key that wraps the data key. Each record uses a fresh random 96-bit nonce and record ID as authenticated associated data. SQLite stores ciphertext, nonce and vault metadata, not plaintext credential fields.

Limitations: local-only does not protect against malware, keyloggers, a compromised OS, malicious browser extensions, physical access to an unlocked device, or insecure backups. Python cannot guarantee zeroization of immutable strings or key bytes in memory. Independent security review is required before production use.
