#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# The shared spacing tool is optional in a standalone checkout. Override its
# location when it is installed outside the parent Open-Source directory.
spacing_formatter="${APOLLO_SOURCE_SPACING_FORMATTER:-$repo_root/../format-source-spacing.py}"
if [[ -f "$spacing_formatter" ]]; then
    python3 "$spacing_formatter" "$repo_root" --check \
        --manifest Cargo.toml --manifest fuzz/Cargo.toml
fi

cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
python3 - <<'PY'
from pathlib import Path

oversized = []
for path in sorted(Path('.').rglob('*.rs')):
    if {'.git', 'target'}.intersection(path.parts):
        continue
    lines = len(path.read_text().splitlines())
    if lines > 500:
        oversized.append(f'{path}: {lines} lines (maximum 500)')
if oversized:
    raise SystemExit('\n'.join(oversized))
print('Rust source files satisfy the 500-line ceiling')
PY

cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo clippy --manifest-path fuzz/Cargo.toml --locked --all-targets -- -D warnings
