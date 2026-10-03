# Capability model

Tokens contain 256 random bits. The daemon stores only an HMAC digest under a
fresh boot-specific key, with namespace/generation, exact secret/version,
recipient/generation, UID/GID/PID/start time, a live pidfd, optional cgroup,
monotonic expiry and remaining-use count. Defaults are 30 seconds and one use.

CURRENT resolves at issuance. Version activation or creation never changes the
version of an existing grant. Caller-supplied delivery metadata cannot widen its
scope because the delivery request has no metadata fields.

Grant consumption is serialized. A successful authorization decrements/removes
the grant before mandatory audit, decryption, FD creation or transport. Failure
after consumption spends that use; retry requires a new grant. A failed issue
transaction removes its tentative grant and returns no token. Revocation fences
capability, recipient generation or namespace generation. Deleted namespaces and
disabled/deleted secrets cannot deliver.

Grants are memory-only. Every crash, restart and restore invalidates all previous
tokens. Expired entries are removed by bounded runtime maintenance and before
new insertion. Capacity/rate limits fail closed.
