# Bounded node115 whole-buffer checksum

A real dependency-free no_std Rust library reconstructing the raw value contract
of leaf61da8b0..61daa52. Its C interface is explicitly chosen for comparison;
no original Rust type/crate or original source version is asserted. A complete
wrapper context proves selected raw-tag2 forwarding with seed0. Other checksum
selectors and streaming state are not implemented. New source/docs MIT.

Non-null inputs require one initialized/readable immutable allocation, length
<=isize::MAX and no address wrap. Byte alignment is unrestricted. Null inputs
ignore raw length and return the seeded empty result, matching the target's
actual early branch. The function does not validate arbitrary pointer metadata.

Actual profile: Rust1.94.1/LLVM21.1.8, Linux x86-64, opt-level2, panic abort,
one codegen unit, LTO off, loop and SLP vectorization explicitly disabled.
Cargo generated the lockfile; no dependencies or root workspace are added.

```sh
RUSTFLAGS='-Cno-vectorize-loops -Cno-vectorize-slp' cargo build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-buffer-hash32/Cargo.toml
python tools/checksum_selector2_rust.py --rustc /path/to/direct/rustc --out-dir work/checksum-comparison
HYPERLIQUID_CHECKSUM_RUSTC=/path/to/direct/rustc python -m unittest discover -s tests -p test_checksum_selector2_rust.py -v
```

On PowerShell set the equivalent $env:RUSTFLAGS and compiler variable before
running commands. Use a new WORK output directory to preserve earlier evidence.
The pinned compiler test skips honestly when not enabled. It interprets only
freshly compiled own code; no captured/native Rust test executable runs.
See the RE-014-checksum-selector2-115 packet for actual counts, controls,
original identity, a manual argument and repository-check limitations.
