# Node #94 cursor-prefix step

Dependency-free, safe `no_std` reconstruction of linked ELF VA
`[0x47d6b90,0x47d6be2)` in node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This standalone crate implements one observed memory transition, not a node
build or a recovered source-level function identity.

`step(image, base, state_offset)` interprets image byte i as address base+i
and uses the recovered state offsets: cursor +0x1d0, counter +0x1e0, flag
+0x1f0 and marker +0x1f3. A zero flag stores marker 0x67. Otherwise an unsigned
counter <=1 stores marker 0x50. Otherwise it stores counter-2, reads a signed
big-endian i16 prefix at the old cursor, and stores cursor+prefix+2 modulo
2^64. Every nonzero flag and every u64 counter is admitted by this rule.

Prefix reads occur **after** the counter store. Prefixes may overlap counter,
cursor, flag, marker or other image bytes; these aliases are preserved. For
example, counter=256 with its first two bytes serving as prefix reads `fe 00`
after decrement and moves by -510, instead of the +3 from the entry `00 01`.
The resulting cursor may be outside the image or wrap; the target only stores
it and does not dereference it again.

Before any writes, the API checks that the image's last address does not wrap
and that the accesses on the selected path fit. The image may end at u64::MAX.
Marker paths do not require a mapped prefix. `AccessError` distinguishes image
range, state bounds and prefix bounds; errors preserve the entire image. This
safe refusal policy is additional behavior: native fault/partial-store behavior
is excluded. The prefix bytes themselves are read only after the counter store,
even though prefix bounds are checked before mutation.

The returned `ObservedRax` expresses the native raw register observation:
unchanged on the zero-flag path, counter on the short-counter path, new cursor
on advance. It does not claim the Rust function physically preserves native
registers or implements the original ABI. Other registers/flags, concurrency,
MMIO, faults, and arbitrary actual mappings of symbolic addresses are outside
the correspondence. All accesses use safe Rust; the fixed-width conversions
are guaranteed by checked eight-byte ranges.

Build and verify from the repository root with Rust 1.94.1:

```sh
CARGO_TARGET_DIR=work/cursor-prefix-cargo cargo build --offline --locked --release \
  --manifest-path src/node94-cursor-prefix-step/Cargo.toml
python3 -O -B research/work-items/RE-001-cursor-prefix-step-rust-94/verify.py \
  --out work/cursor-prefix-review
```

The [evidence packet](../../research/work-items/RE-001-cursor-prefix-step-rust-94/README.md)
and [proof](../../research/work-items/RE-001-cursor-prefix-step-rust-94/PROOF.md)
contain full target/FDE/relocation bindings, independent pre-Rust expectations,
input-only native comparison, repeated artifacts and effective mutation controls.
Only newly authored Rust is executed; no captured target or instruction emulator.
