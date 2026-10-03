# systemd deployment

Install the release binaries in a root-owned executable directory. Create the
static dedicated user from packaging/sysusers.d. Install the packaged service and
configure a protected exact 32-byte root at `/etc/apollo-secretsd/root` (root-owned
0400/0600). Label it for the host's enforcing SELinux policy, normally etc_t;
do not place LoadCredential sources under an inaccessible home-directory label.
Never log the credential while provisioning. Keep a secure recovery copy outside
encrypted state backups, according to your provider policy.

The unit uses Type=notify, StateDirectory mode 0700, RuntimeDirectory mode 0755,
systemd credential delivery, required secret memory, no privileges/capabilities,
private network/devices/tmp, strict filesystem/home protections, AF_UNIX only,
restricted syscall/namespace/personality behavior, zero core limit, 128 MiB
memlock, 32,768 FDs, eight tasks and a 256 MiB cgroup memory limit. A static UID
supports stable state/socket ownership and process credential checks.

`ProtectProc=invisible` hides other UIDs from the service's own procfs mount.
With zero capabilities it prevents the cross-UID recipient
`status`, `stat`, and `cgroup` reads required for kernel identity checks. It does
not hide the daemon from processes outside that mount. The unit therefore uses
`ProtectProc=default`; dumpability/core and memory protections remain mandatory.
The unit uses `ProcSubset=all` so provider and library operations can access
the procfs paths they require.

`RestrictSUIDSGID=no` is a required exception for the credential provider:
systemd otherwise returns ENOSYS for every `openat2` call because its seccomp
filter cannot inspect the indirect creation mode. Credential and state traversal
retain `openat2`'s no-symlink resolution. The daemon uses fixed 0600 file creation
modes, never executes programs, has no capabilities and retains
`NoNewPrivileges=yes`. See the [systemd implementation](https://github.com/systemd/systemd/blob/v259/src/shared/seccomp-util.c)
and [upstream compatibility report](https://github.com/systemd/systemd/issues/38711).

Validate `systemd-analyze verify`, then inspect actual readiness and run
`apollo-secretsctl doctor --state ... --runtime ... --socket ... --server-uid UID
--unit apollo-secretsd.service` as an authorized administrator. Doctor checks
kernel primitives, process protections, configured ownership/modes, SQLite/WAL,
authenticated live audit and selected systemd properties. It does not certify
unqueried host policy or hardware firmware.

For TPM mode, build the feature, install the example drop-in after replacing all
handle/Name placeholders, grant only `/dev/tpmrm0`, and supply the auth credential.
