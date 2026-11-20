# MCPMac Rust 1.89 compatibility backport

This is the crates.io `p3-util 0.8.0` archive from Plonky3 commit
`a21e3ed42905040ad49c519e402f018381c12d0c`, with one code change in
`src/lib.rs::apply_to_chunks`. `upstream-source.json` records the archive and
original file SHA256 values. The other dependency versions are retained.

The upstream slice `MaybeUninit::assume_init_ref` call requires a newer compiler.
The replacement uses stable `core::slice::from_raw_parts` over the initialized
byte prefix. The preceding helper initializes exactly `n` bytes, `n <= BUFLEN`,
and `MaybeUninit<u8>` and `u8` have identical size/alignment. The callback receives
the same immutable slice during the buffer's lifetime. The algorithm, chunk
boundaries, handling of empty input and cryptographic parameters are unchanged.

The registry cache markers and nested upstream lockfile are omitted. All other
archive files are retained. The upstream MIT and Apache licenses are included
from the same pinned repository commit; the crate remains dual licensed.

Run the workspace check with Rust 1.89 and the upstream utility tests, including
the six `test_apply_to_chunks_*` cases. The phase-one compatibility evidence
records actual outcomes. Remove this patch only after a reviewed upstream release
and a fresh locked Rust 1.89 build; do not replace it by editing a Cargo cache or
enabling unstable compiler features.
