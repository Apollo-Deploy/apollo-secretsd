# Generic caller integration

A trusted controller administers opaque namespaces/secrets and captures the
actual recipient PID/UID/GID. It issues a grant for an exact immutable version,
recipient ID/generation and TTL/use count. It transfers the sealed capability FD
over a designated inherited Unix channel. The recipient reads the token into
protected memory and submits only those 32 bytes to deliver.sock, then validates
and uses the sealed secret FD returned by the client.

`examples/generic_recipient.rs` accepts an inherited channel FD, delivery socket
path and expected server UID. It receives a `grant` descriptor, redeems through
the public client and sends a `secret` descriptor back through the controller
channel. The example contains no namespace, project, container, VM or Apollo
service vocabulary. A sandbox/orchestrator can inject that FD through its own
guest protocol; secretsd does not know that protocol.

`apollo-secretsctl grant issue ... --out-fd N` uses the same inherited Unix
channel contract; it never prints token bytes. Secret create/put values enter
via `--stdin`, `--file` or `--fd`, never argv. For a daemon under a separate UID,
set `--server-uid` explicitly. Names/metadata are administrative information;
normal response metadata does not authorize delivery.

Close capability and delivery descriptors promptly. Reissue after expiry,
consumption, revocation, process replacement or restart. Do not retry a consumed
grant after a transport failure; already delivered bytes remain recipient-owned.
