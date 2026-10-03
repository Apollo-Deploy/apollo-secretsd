# Namespace isolation

Opaque namespaces own opaque secret IDs and immutable version numbers. The
same secret name can exist in two namespaces; its blind name index includes the
namespace. Every lookup and crypto operation carries that namespace and secret
together. Numeric versions are never global identifiers.

Administrative namespace creation/deletion and generation changes are audited
transactions. Deletion leaves authenticated history and tombstones. New
namespaces have fresh random IDs. Recipient and namespace generation fences are
revalidated against authenticated current records at each redemption.

SO_PEERCRED is checked against per-packet SCM_CREDENTIALS. Linux SO_PEERPIDFD
pins the socket's original peer PID object, eliminating numeric PID reopening
at the socket boundary. Process capture verifies procfs effective identity/start
time and pidfd liveness; grants independently retain their recipient pidfd.
Socket transfer to a different sender does not transfer identity authority.

Isolation tests cover same-UID, same-name namespaces, cross-scope ID
substitution, exact version pinning and generation/revocation checks.
