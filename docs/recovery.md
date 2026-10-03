# Recovery

Keep the daemon stopped while investigating an integrity/protection error. Never
delete rows, change FULL durability, skip MAC checks, or substitute a new root to
make an existing database open. Preserve an encrypted forensic copy of the state
directory and redacted journal. Startup diagnostics identify static phases and
errno without printing provider or secret bytes.

After a crash, restart with the same provider and safe directory ownership.
SQLite recovers committed WAL state; startup reauthenticates records and audit.
An in-progress KEK rotation retains both wrapped KEKs and its authenticated cursor,
so bounded maintenance resumes. Use status, audit verify and key status before
issuing new grants. All previous grants are invalid across restart.

If storage is full or locked, requests may fail without acknowledgment. Remove
unrelated filler/free capacity safely or release the competing writer; retry the
administrative operation after authenticated readiness. An ambiguous transport
failure may have followed a committed mutation: inspect metadata/version state
before retrying. Client operation IDs correlate responses and do not provide
automatic administrative idempotency.

Use a verified encrypted backup with its correct provider if current state cannot
authenticate. A wrong root or individually altered/replayed record fails closed.
There is no recovery/backdoor key.
