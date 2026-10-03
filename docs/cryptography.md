# Cryptography

Maintained RustCrypto XChaCha20Poly1305 encrypts every immutable version using a
fresh random 32-byte DEK and independent random 24-byte nonces. The DEK is wrapped
by a random KEK, itself wrapped by the provider root. Payload and name metadata
are separate authenticated envelopes. AEAD tags are 16 bytes.

Canonical binary AAD binds domain/format, namespace, secret, immutable version,
blob type, algorithm and the wrapping KEK where applicable. Payload/name AAD
remains stable during KEK rotation; rewrapping changes only the wrapped DEK.
Associated data is recomputed from the authorized scope, not trusted from a row.

HKDF-SHA256 separates state authentication, audit chain, name index and capability
digest keys. Grant derivation additionally uses fresh boot randomness. HMAC-SHA256
includes length-prefixes for each part. State MAC binds kind/key/body. Constant-time
MAC verification comes from the maintained library. The storage-record format is
2; the envelope/KDF domain version remains 1.

This build is not a FIPS-validated implementation. Native crypto tests exercise
scope/version substitution, nonce/ciphertext/tag/wrapped-DEK tampering and stable
payload ciphertext during rewrapping. Dependencies/features are pinned in
Cargo.lock. Use `cargo audit` and `cargo deny` to check dependencies.

The direct `poly1305` dependency intentionally enables its `zeroize` feature
through Cargo feature unification. `chacha20poly1305/zeroize` does not forward
that feature in the pinned release; removing the direct edge would stop clearing
the internal Poly1305 state on drop. It is required even without a source import.
