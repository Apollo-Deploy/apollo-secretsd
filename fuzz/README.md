# Protocol fuzzing

The libFuzzer target checks arbitrary bounded frames, canonical admin/response
messages, exact token-only redemption and redacted token formatting. It exercises
the exported protocol crate used by both client and daemon. It does not claim to
fuzz kernel ancillary parsing or replace native socket and process tests.

```sh
cargo +nightly fuzz run frame_and_messages -- -max_total_time=300 -max_len=70000
```

Retain crashing inputs and fix their underlying cause before continuing. Corpus
inputs are synthetic protocol data; never seed this directory with real secrets.
