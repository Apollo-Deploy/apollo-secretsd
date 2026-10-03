# Architecture

The workspace owns `apollo-secretsd`, `apollo-secretsctl`, and
`secretsd-protocol`. It imports upstream libraries and has no dependency on an
Apollo service, registry, schema, network endpoint, or orchestrator.

`admin.sock` and `deliver.sock` are AF_UNIX SOCK_SEQPACKET listeners. A mio/epoll
loop bounds connections and request buffers, then submits one request per
connection to a finite queue. Two protected-stack workers share a serialized
authority boundary. That boundary checks authorization, consumes grants,
persists mandatory audit, and only then decrypts exact immutable versions.
Replies carry metadata plus at most one sealed anonymous descriptor.

`service/` owns policy; `capability/` owns boot-local digest grants;
`auth.rs` owns kernel peer identity; `crypto/` owns envelopes and derivation;
`storage/` owns authenticated durable records/audit/rotation; `memory/` owns
protected buffers and stacks. Public Rust service APIs assume a trusted embedding
caller. The Unix runtime authenticates untrusted callers.

The daemon neither starts subprocesses nor opens TCP/UDP sockets. The separate
doctor CLI invokes the fixed systemctl executable to inspect its configured unit.
