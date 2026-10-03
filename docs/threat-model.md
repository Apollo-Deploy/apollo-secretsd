# Threat model

Untrusted local recipients may guess identifiers, share a UID, replay grants,
hand off sockets, race redemption, or submit malformed packets. Possession of a
namespace, name, or secret ID grants no delivery authority. Recipient identity is
kernel-derived and a capability pins an exact version and process incarnation.

Run the daemon under a dedicated static service UID. Give untrusted workloads
different service identities; do not share the daemon's UID or state directory.
Root administrators and the controller are trusted. Compromise of the daemon,
authorized controller, kernel, root, or a recipient intentionally disclosing an
already delivered value is outside this boundary.

State authentication detects modified rows, cross-scope ciphertext substitution,
and individual old-row replay against the authenticated audit history. A complete
valid database snapshot can be rolled back with its entire audit history: there
is no external monotonic freshness anchor. All old grants still disappear across
restart because their digests use a fresh boot key.

Memory locking and dump exclusions do not protect against a privileged kernel
reading RAM. A software TPM qualifies TPM protocol behavior; it does not add
hardware protection against a host administrator.
