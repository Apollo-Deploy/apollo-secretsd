# Protocol

Protocol v1 uses one SOCK_SEQPACKET request and response per connection. The
maximum frame is 65,536 bytes. Its 28-byte header is big-endian: `ASD1` magic,
u16 version, u16 message type, nonzero 16-byte operation ID, u32 payload length.
Types are admin request 1, admin response 2, redeem request 3, delivery response 4.
The operation ID is echoed and validated by the client.

Admin bodies use the public prost types in `secretsd-protocol/src/admin.rs`.
Decoding must re-encode identically: unknown fields, duplicate/noncanonical
encodings and incompatible versions are rejected. A secret create/put request
declares exact length and supplies one fully sealed SCM_RIGHTS FD. Grant issuance
returns one sealed 32-byte capability FD. Redeem payload is exactly 32 token bytes;
it contains no IDs, generation, UID, PID, name, or caller-selected scope.

Responses contain stable error codes, opaque IDs, status/metadata and an FD length.
Error codes are OK 0, Invalid 1, Denied 2, NotFound 3, Limit 4, Unavailable 5,
Integrity 6, Conflict 7. Errors include no sensitive bytes. The client verifies
server UID, kernel packet credentials, message/operation identity, FD count,
exact size and all seals. See [delivery](delivery.md).

Idle connections and completed replies have a five second transport deadline.
An admitted request retains its bounded connection slot until its worker finishes;
the reply deadline starts at completion. Workers and queued work remain bounded.
The public Client bounds each connect/send/receive to five seconds. A timeout or
disconnect may occur after consumption or a durable admin mutation: it does not
prove rollback or receipt. A spent one-shot use requires a newly issued grant;
never infer delivery from a CapabilityRedeem audit event alone.
