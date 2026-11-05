# Threat model

Assets: vault master password, derived keys, encrypted credential records, local session secret.

In scope: copied database while locked, accidental plaintext logging, ciphertext tampering, password guessing, and unintended network exposure.

Out of scope/residual risks: malware, keyloggers, compromised operating systems, malicious browser extensions, physical access to an unlocked device, memory inspection, and insecure backups.

Controls: Argon2id key derivation, AES-256-GCM authenticated encryption, random per-operation nonces, loopback binding, CSRF protection, no-store headers, hidden CLI password prompts, and no credential logging.
