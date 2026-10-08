# Security

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub security advisories](https://github.com/maulai/vaultty/security/advisories/new), not in public issues. Only the latest release receives fixes.

## Threat model

vaultty protects the vault file at rest. Whoever gets a copy of the file needs the master password, and every guess costs 256 MiB of memory and three Argon2id passes.

It does not protect against malware or another user with access to the machine while the vault is unlocked. Decrypted data and key material are in process memory then. Go cannot wipe every copy, so some may remain, even after locking, until the memory is reused. Lock the vault when you step away; it stays unlocked while an SSH session is open.

<kbd>ctrl</kbd>+<kbd>]</kbd> types the stored password into the remote terminal. Use it only at a password prompt.

## Vault file format

All integers are big endian.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 7 | magic `SSHVLT2` |
| 7 | 1 | format version, `2` |
| 8 | 1 | KDF, `1` = Argon2id |
| 9 | 4 | Argon2id passes |
| 13 | 4 | Argon2id memory in KiB |
| 17 | 1 | Argon2id lanes |
| 18 | 16 | salt |
| 34 | 12 | nonce |
| 46 | rest | AES-256-GCM ciphertext and tag |

The 32 byte key is `Argon2id(password, salt)` with the parameters from the header. The password is normalized to Unicode NFC first (RFC 8265), so the same characters typed on different systems give the same key. The magic is the additional authenticated data. The KDF parameters and the salt are bound to the ciphertext through the key, so changing any of them makes decryption fail.

Header values come from an untrusted file and are checked before use: 1 to 10 passes, 1 to 64 lanes, at most 4 GiB of memory. On unlock, a vault below the current default (256 MiB, 3 passes, 4 lanes) is re-encrypted with a new salt and the default. This only happens when neither memory nor passes would go down.

The plaintext is UTF-8 JSON with the schema version, folders, key profiles, trusted host keys and hosts.
