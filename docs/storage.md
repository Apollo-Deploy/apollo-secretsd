# Storage

Only encrypted immutable versions, wrapped keys, authenticated control records
and metadata-only audit are durable. Secret names are encrypted under each DEK
and indexed by namespace-scoped HMAC. Deleted names/versions/history remain
reserved and count toward quotas; there is no unauthenticated garbage collector.

State directory ownership is the dedicated service UID, mode 0700. Database,
WAL, SHM and lock files must be regular, mode 0600, one link and owned by that
UID. openat2 rejects symlink and magic-link paths. SQLite paths resolve from a
pinned directory descriptor, rather than reopening the original pathname.

SQLite uses WAL, synchronous FULL, 250ms busy timeout, foreign keys, trusted_schema
OFF, disabled mmap, 1 MiB page cache and memory-only temporary storage. A 4 MiB
plus overhead SQLite row limit bounds hostile on-disk blob allocation. Mutations
use BEGIN IMMEDIATE and include version, active pointer, name index, authenticated
quota checkpoint and audit in one commit. Success follows the commit.

Startup checks SQLite integrity, format compatibility, every state MAC, audit
chain/tip, current record transitions and total ciphertext bytes. Current row tags
are also checked before live reads/writes. The record-format version is 2;
unsupported formats fail closed. Global authenticated records are bounded at
100,000, in addition to configurable per-resource ceilings.
