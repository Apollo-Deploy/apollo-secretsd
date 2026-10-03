# Delivery

Successful redemption creates an exact-size anonymous memfd. Its pages remain
locked through the writable-to-readonly transition. The sender verifies
F_SEAL_WRITE, F_SEAL_GROW, F_SEAL_SHRINK and F_SEAL_SEAL before transfer. SCM_RIGHTS
carries a read-only FD with a metadata response; no secret bytes appear in the
response body, logs or a named temporary file.

Clients verify kernel server credentials, expected FD count and length, regular
file type and all four seals before reading. Received descriptors use CLOEXEC.
Malformed/truncated ancillary data is rejected and owned FDs close on failure.
The recipient owns the delivered FD after transfer; close it promptly after the
intended injection/use. Already delivered bytes cannot be revoked retroactively.

There is no caller-selected pathname or plaintext get/reveal CLI. The optional
caller-FD delivery extension is not enabled. Use the sealed descriptor contract.
Native tests verify exact bytes and rejection of write, shrink, grow and seal
removal; the runtime race checks one-shot semantics through actual Unix sockets.
