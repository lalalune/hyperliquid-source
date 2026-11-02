# node94 two-table signed lookup

An independently authored, safe `no_std` value component for the complete
node94 leaf `[0x5560660,0x55606a8)`. It returns the full 64-bit qword in RAX
from a supplied stable runtime byte image. It needs no dependency, allocation,
unsafe code, root Cargo workspace or captured executable.

```rust
pub fn lookup(
    image: &[u8], image_base: u64, load_bias: u64,
    first: u64, mode: u64, row: u64,
) -> Result<u64, AccessError>;
```

The raw inputs represent RDI, RSI and RDX. Let `x = first mod 2^32`,
`m = mode mod 2^32`, `y = signed32(row mod 2^32)`. If x is 3, 4 or 5 and
m is 1, read at `(load_bias + 0x576db20 + 8*(x-3) + 24*y) mod 2^64`.
Otherwise read at `(load_bias + 0x576d9e0 + 8*signed32(x) + 80*y) mod 2^64`.
Each read is one little-endian u64, including all its high bits.

The image's numeric address range must not wrap, and the selected eight
bytes must all fit it. The new errors `ImageRange` and `SelectedWord`
refuse invalid descriptions and reads. They do not reproduce hardware faults.
The image is immutable; both paths read only the selected qword. There is
no guessed table length, domain cap or requirement to contain either linked
base when the selected address lies elsewhere.

This is a value API rather than the original machine ABI. Correspondence
requires actual runtime bytes and load bias, stable ordinary memory and a
normally completing original read. Synthetic numeric addresses in tests do
not assert that such addresses are canonical or mapped on x86. Other
caller-clobbered registers, flags, instruction/return-stack behavior, faults,
concurrent memory, MMIO and timing are outside scope. No source-library or
original compiled-byte identity is claimed.

The target has SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
[Proof and evidence](../../research/work-items/RE-004-two-table-lookup-rust-94/README.md)
close the two signed affine address rules, FDE/body/caller, both linked-base
bindings and their relocated base-qword samples. Arbitrary selected runtime
contents are API inputs, not invented constant target tables.

From the repository root, with the recorded Apple host compiler installed:

```sh
python3 -O research/work-items/RE-004-two-table-lookup-rust-94/verify_rust.py \
  --rustc "$HOME/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc" \
  --out work/two-table-lookup-rust/replay
```

Use a fresh output directory. The verifier pins the compiler's actual bytes
and version, rebuilds the library and input-only client at opt0 and opt3,
runs all frozen cases and real compiled controls, repeats builds without
normalization and retains exact command streams in a lossless archive.
This is native execution of newly authored Rust only.
