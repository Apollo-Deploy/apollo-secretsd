# Memory protection

Startup requires PR_SET_DUMPABLE=0 and hard/soft RLIMIT_CORE=0. Owned plaintext,
root, derived-key and DEK mappings use mlock and MADV_DONTDUMP; ordinary owned
buffers also use MADV_WIPEONFORK and are erased, including padding, before release.
They do not implement Clone or expose bytes through Debug. Crypto/bootstrap
workers use owned locked, excluded, guarded pthread stacks erased after join.

The root moves to memfd_secret when available. `--require-secret-memory` makes
absence fatal. Automatic mode permits ordinary locked storage only on ENOSYS;
permission/resource errors fail closed. Secret mappings use close-on-exec and
MADV_DONTFORK. The supported service unit requires secret memory explicitly.

The daemon additionally locks its address space (MCL_CURRENT|MCL_FUTURE) and limits
glibc arenas. This protects temporary native TPM allocations and metadata strings
from swap. Sensitive protocol names and response buffers are erased on drop.
There is no plaintext cache. Decryption occurs only after grant consumption/audit.

Owned mapping budget is separate from the kernel's full process memlock limit;
both must be sufficient. The unit supplies 128 MiB memlock. Locked-memory,
allocation or protection failure denies service rather than weakening protections.

These controls do not defeat a privileged kernel.
