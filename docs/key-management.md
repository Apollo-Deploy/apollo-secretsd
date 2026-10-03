# Key management

Provide exactly one 32-byte root provider. Prefer an inherited protected FD or
systemd credential. `--key-fd N` consumes an inherited descriptor (N >= 3);
`--credential NAME` opens a validated basename under CREDENTIALS_DIRECTORY with
openat2 and no symlink traversal. The inherited-FD provider accepts fully sealed
memfds or private regular files owned by the effective UID, mode 0400/0600,
one link and exactly 32 bytes. The launcher must prevent concurrent writers.

The systemd provider separately validates the pinned credential directory and
file on a read-only tmpfs/ramfs. Private owner-owned credentials use directory
0500 and file 0400. Root-owned credentials delivered to a service UID use
directory 0550 and file 0440 with an exact POSIX ACL granting only that service
UID the required read/traversal rights; group and other entries grant nothing.
Additional named principals, writable storage, symlinks and unexpected modes
fail closed. This accepts systemd's actual credential delivery without broadening
the inherited-FD provider's file contract.

`--key-file PATH` is a fallback: regular file, root-owned, 0400/0600, one link,
exactly 32 bytes, no symlink/magic-link traversal. Do not place values on argv or
print the root. Losing the root and all valid provider recovery material loses
access to stored secrets. There is no backdoor key.

Build with `--features tpm2` for the maintained tss-esapi device provider. Configure
`--tpm2 SEALED:SALT:AUTH_SOURCE:SEALED_NAME:SALT_NAME`, where handles are hex,
AUTH_SOURCE is an inherited FD number or `credential=NAME`, and each trusted
SHA256 TPM Name is 68 hex characters beginning 000b. The fixed TCTI is
`/dev/tpmrm0`; both public Names and object roles are pinned. Unsealing uses a
salted AES256-CFB/SHA256 HMAC session with parameter encryption. TPM is optional
for deployment; choose a recovery policy appropriate to the provider.

`key rotate` starts online random-KEK rotation. Durable batches rewrap DEKs and
advance an authenticated cursor, then retire the old KEK only after completion.
Use `key status` to inspect pending/completed state. Root-provider migration is
not the same operation as KEK rotation; preserve the configured root for restore.
