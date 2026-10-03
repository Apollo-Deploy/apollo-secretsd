# apollo-secretsd

A standalone Linux-local Rust secrets broker. Administrators manage encrypted,
immutable secret versions over `admin.sock`. Recipients redeem short-lived,
process-bound capabilities over `deliver.sock` and receive sealed anonymous file
descriptors.

Secrets are scoped to namespaces. The daemon authenticates local callers using
kernel credentials and pidfds, encrypts stored values, and maintains an
authenticated audit chain. It has no dependency on another Apollo service.

## Build

Use Rust 1.93 or newer and Linux 6.5 or newer. The kernel must support SO_PEERPIDFD;
peer inspection requires readable procfs and unified cgroup metadata.

```sh
cargo build --locked --release
cargo test --locked --workspace
./scripts/lint.sh
```

TPM is optional. The default build supports protected file descriptors, systemd
credentials, and a strict root-key file. Build with `--features tpm2` for a TPM2
provider exposed at `/dev/tpmrm0`; see [key management](docs/key-management.md).

## Run

Create separate state (0700) and runtime (0755) directories owned by the daemon's
UID. Supply exactly one root-key provider. The systemd unit and sysusers
configuration are in [packaging](packaging/).

```sh
apollo-secretsd --state /var/lib/apollo-secretsd --runtime /run/apollo-secretsd \
  --admin-uids 0 --credential master-key
apollo-secretsctl --help
```

Secret values enter through stdin, a file descriptor, or an input file. Capability
tokens are transferred as sealed file descriptors through an inherited Unix
socket selected with `--out-fd`. Neither values nor tokens are CLI arguments.

See the [architecture](docs/architecture.md), [protocol](docs/protocol.md),
[caller integration](docs/integration.md), [systemd setup](docs/systemd-hardening.md),
and [recipient example](examples/generic_recipient.rs). The [threat model](docs/threat-model.md)
describes the security boundaries.

## License

[MIT](LICENSE).
