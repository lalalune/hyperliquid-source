# RE-002: which node115 functions are the published rustc 1.95.0 standard library?

- Component ID: foundation (dependency-tagged windows only; no first-party credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain basis: node115 `.comment` names `rustc version 1.95.0 (59807616e 2026-04-14)`
  and LLD 22.1.2. The source objects are the published `rust-std` component
  for `x86_64-unknown-linux-gnu` of that release (`rustup target add
  x86_64-unknown-linux-gnu --toolchain 1.95.0`). Input rlib hashes are in `census.json`.
- Claim status: observation (static parsing only)

## Reproduce

```sh
rustup target add x86_64-unknown-linux-gnu --toolchain 1.95.0
python3 research/work-items/RE-002-node115-std-census/census.py \
  "$(rustc +1.95.0 --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/lib"
make catalogue catalogue-check
```

## Method

Every FUNC symbol that exactly covers a `.text*` section in the core, alloc,
std and compiler_builtins rlib objects is a candidate body. A candidate is kept
when:

- its only relocations are 4-byte PC32, PLT32 or GOTPCREL fields (those exact
  bytes are masked; nothing else is normalized);
- at least half its bytes are unmasked and it is at least 16 bytes long;
- exactly one node115 `.text` FDE with a non-duplicated start has the same
  length and equal unmasked bytes;
- no different source body claims the same node115 FDE. Byte-identical bodies
  under another symbol or codegen unit are recorded as `identical_sources` or
  `aliases`.

`bodies.bin` holds the retained source bodies; each byte-window record points
to its offset and relocation list in `census.json`. The bodies are compiled
Rust standard-library code (MIT OR Apache-2.0); `rust-COPYRIGHT` and
`rust-LICENSE-MIT` are the upstream notices.

## Results

| Dependency | Windows | Bytes | Raw-equal windows |
| --- | ---: | ---: | ---: |
| rust-core | 112 | 39,873 | 5 |
| rust-std | 174 | 60,556 | 16 |
| compiler-builtins | 13 | 2,874 | 5 |
| rust-alloc | 9 | 838 | 0 |

All 308 are relocation-qualified. Two overlap the existing `DebugStruct::field`
and `__floatuntidf` windows (RE-002-node115-dependency-windows,
RE-004-node115-u128-binary64). The census finds those same functions
independently; they keep their earlier records, so 306 new windows are
registered. `__umodti3` from 1.95.0 is raw-equal at `0x63efd70`. The 1.94.1
body used for the retired historical capture differs there in 45 bytes, so
dependency sources must come from the toolchain named in node115's `.comment`.

## Limitations

- Only std functions emitted out of line in the published rlibs. Generic
  std code instantiated inside node crates needs the node's own build.
- Relocation fields are masked, not resolved. GOTPCRELX relaxation would show up
  as a non-relocation difference, so such bodies are excluded rather than normalized.
- No component gate, behavior or source-build claim.

Next question: which vendored crate sources and codegen flags reproduce the
generic std instantiations and `z_vendor` code (see RE-002-node115-vendor-inventory)?
