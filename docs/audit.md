# Audit

Audit events contain timestamp/sequence/type, opaque namespace/object IDs,
kernel UID/PID and authenticated state-transition tags. They contain no name,
payload, root, DEK, KEK or plaintext capability. Each HMAC binds sequence/body and
the previous chain tip. The authenticated header checkpoints sequence and tip.

Every security mutation and accepted/rejected redemption requires a durable
audit transaction. Audit failure denies the operation. Successful authorization
has already consumed its grant use; an audit/decrypt/transport failure cannot
restore that use. Startup, key operations, namespace/secret changes and revocations
are journaled. Malformed transport packets dropped before authentication do not
become trusted audit metadata and may close without a response.

`audit verify` checks authenticated state and the complete chain. Every `audit tail`
validates the complete authenticated chain against the in-memory checkpoint before
returning its bounded page. Verification and page selection share one SQLite read
transaction, so a live writer cannot replace rows between them. A gap or truncated
chain fails closed even outside the requested page. `audit tail`
returns bounded metadata; `--after` and `--limit` paginate. Audit has an explicit
record quota and retained history consumes disk. Monitor storage and rotate
operational encrypted backups before reaching the limit. Do not truncate or
rewrite the chain manually; that breaks verification. Whole-snapshot rollback
needs an external freshness policy, as explained in the threat model.
