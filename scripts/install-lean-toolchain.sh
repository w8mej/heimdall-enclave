#!/usr/bin/env bash
# Pinned Elan release + SHA256; pinned Lean version comes from the repository.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
case "$(uname -s)-$(uname -m)" in
Linux-x86_64)
	triple=x86_64-unknown-linux-gnu
	digest=42b94d4244e8353142c456ec0e4ca6528fd898a6c604d4059f494e706e431f63
	;;
Darwin-arm64)
	triple=aarch64-apple-darwin
	digest=7ad829861392c718dfebde3a83b5c8508df47be02af68894b094b0b3952616e5
	;;
Darwin-x86_64)
	triple=x86_64-apple-darwin
	digest=8a340b309d8ed2e96f930761fa223b3af57a38f5d253b53ac90293c9516f8cd4
	;;
*)
	echo 'BLOCKED: unsupported host for pinned Elan installation' >&2
	exit 2
	;;
esac
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT
curl --fail --location --silent --show-error \
	"https://github.com/leanprover/elan/releases/download/v4.2.4/elan-${triple}.tar.gz" \
	-o "$scratch_dir/elan.tar.gz"
python3 - "$scratch_dir/elan.tar.gz" "$digest" <<'PY'
from pathlib import Path
import hashlib, sys
if hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit('FAIL: Elan archive digest mismatch')
PY
tar -xzf "$scratch_dir/elan.tar.gz" -C "$scratch_dir"
"$scratch_dir/elan-init" -y --no-modify-path --default-toolchain none
export PATH="${ELAN_HOME:-$HOME/.elan}/bin:$PATH"
cd "$repo_root/proofs/lean4"
elan toolchain install "$(cat lean-toolchain)"
lean --version
lake --version
