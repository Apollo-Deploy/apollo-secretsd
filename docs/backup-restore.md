# Encrypted backup and restore

Quiesce administration and stop the daemon cleanly. With the process stopped,
checkpoint SQLite WAL using a maintained SQLite tool/library, then copy the entire
private state directory (database and any remaining WAL/SHM) into a new private
directory. Do not copy only the live database while a writer runs. Preserve 0700
directory and 0600 file ownership/modes, and fsync copied files and destination
directory before declaring backup durable. Store the archive in access-controlled
encrypted backup storage with a retention policy.

The backup contains ciphertext, wrapped keys, IDs and audit, never plaintext
secret values, tokens or unwrapped KEKs. The configured root/provider material is
managed separately and must survive the loss of this host. A TPM-bound root needs
a provider-specific validated recovery policy; copying its handles is not a
portable root-key backup.

Restore into an isolated new state directory owned by the dedicated daemon user,
with correct modes. Supply the original provider root and a separate runtime
directory. Verify authenticated readiness, audit, exact immutable-version delivery
and rotation status before switching service. Restore with an incorrect root must
fail before readiness. Never restore old token authority: every boot invalidates
grants. A valid old whole snapshot may be stale; compare against your external
backup/freshness records. Do not merge rows from different snapshots.
