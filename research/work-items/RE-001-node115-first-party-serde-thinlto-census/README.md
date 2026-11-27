# RE-001: node115 first-party `serde::Deserialize` field-visitor census (ThinLTO + `tikv-jemallocator`)

- Components: 12 first-party components (see table); no dependency credit
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`,
  `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `serde = "=1.0.229"`,
  `serde_json = "=1.0.154"`, `rmp-serde = "=1.3.0"`, `RUSTFLAGS="-C save-temps"`
- Claim status: observation (static parsing + clean-room rebuild; no target execution)

## What this proves

`#[derive(serde::Deserialize)]` on Hyperliquid's own enums and
`#[serde(deny_unknown_fields)]` structs generates `__FieldVisitor::visit_bytes`
functions. Under node #115's exact release profile (ThinLTO plus
`tikv-jemallocator`, which inlines `_rjem_je_sdallocx` into the
`String::from_utf8_lossy` cleanup path), the compiled bodies equal node #115's
`.text` FDEs up to relocation fields.

**162 windows, 166,298 bytes, 100% relocation-qualified, 0 GOTPCRELX relaxations,
0 raw-equal** (every body has at least one masked PC-relative field).

| Component | Windows | Bytes |
| --- | ---: | ---: |
| `action-wire` | 36 | 75,561 |
| `dex-registry` | 22 | 32,074 |
| `staking` | 43 | 27,013 |
| `risk` | 18 | 6,660 |
| `assets` | 2 | 5,684 |
| `fees` | 6 | 4,509 |
| `vaults` | 9 | 4,134 |
| `orderbook` | 9 | 3,738 |
| `bridge` | 6 | 2,952 |
| `exchange` | 6 | 2,880 |
| `abci` | 3 | 561 |
| `node-runtime` | 2 | 532 |
| **Total** | **162** | **166,298** |

The largest single body is the 92-variant top-level L1 `Action` tag visitor
(`0x2b9cdb0`, `0x365d9d0`, `0x4d63870`; 15,538 B each).

## Admission gates (all enforced by `census.py --verify`)

1. The window is a complete, uniquely-started node #115 `.text` FDE, at least 16
   bytes, with relocation-masked bytes at most half its length, and passes
   `tools/byte_progress.compare` as relocation-qualified.
2. **Data-identity anchor:** one of the body's PC32 relocations, resolved in
   node #115, points to a `.data.rel.ro` `&[&str]` slice. The slice's pointers
   (from `.rela.dyn` `R_X86_64_RELATIVE` entries) and lengths must spell the
   family's complete, ordered variant/field list in `.rodata`, byte for byte.
   Code shape alone is not enough to admit a window.
3. Zero overlap with every non-`node115-fp-serde-*` window in
   `research/byte-windows.json` and with every sibling `records.json` packet.
4. Only harness CGUs (`hl_node115_serde_census-*.rcgu.o`) are scanned; vendor
   CGUs (`*.rcgu.o.rcgu.o`) are excluded.

## Attribution (conservative)

The binary has 74 enum and 107 struct field-name tables that reach serde's
`unknown_variant` / `unknown_field` helpers (`0x17fbba0`, `0x2cf1360`,
`0x17fbab0`, `0x2cf1270`). Only **22 enums and 34 structs** are admitted here:

- 54 families whose exact string list already carries a reviewed component in
  `RE-001-node115-first-party-byte-census/wave3_specs.json` (Wave 3 `visit_str`);
- 2 families attributed by exact identity: the 92-variant L1 `Action` tag set
  (`noop`, `approveAgent`, ... → `action-wire`) and the 55-variant info request
  set (`fileSnapshot`, `webData2`, ... → `info-api`).

**Excluded:** 6 third-party serde families (alloy `Filter`, `BlockNumHash`
request, blob sidecar, `AccountOverride`, `TxType` names, and an EVM call-result
enum), plus **119 first-party families with no reviewed component mapping
(about 681 KB of node FDE extent).** They need a per-family component review
before they can be admitted. They are compiled in `harness/src/main.rs` but get
no credit, because `family_meta.json` lists only the admitted families.

## Reproduce

```sh
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=work/target/fp-serde RUSTFLAGS="-C save-temps" \
  cargo +1.95.0 build --locked --release --target x86_64-unknown-linux-gnu \
  --manifest-path research/work-items/RE-001-node115-first-party-serde-thinlto-census/harness/Cargo.toml
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serde-thinlto-census/census.py \
  work/target/fp-serde/x86_64-unknown-linux-gnu/release/deps \
  research/work-items/RE-001-node115-first-party-serde-thinlto-census/harness/Cargo.lock \
  research/work-items/RE-001-node115-first-party-serde-thinlto-census/family_meta.json
```

Verify:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serde-thinlto-census/census.py --verify
(cd research/work-items/RE-001-node115-first-party-serde-thinlto-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_serde_thinlto_census_115 -v
```

## Limits

- `visit_str` bodies for these families were already credited by Wave 3, so
  overlap exclusion leaves only `visit_bytes` bodies here.
- `RE-001-node115-first-party-byte-census/census.py` excludes every
  `node115-fp-*` window when it checks overlap. A future regeneration of that
  packet must also exclude the `node115-fp-serde-*` intervals.
- No gate credit or behavior claim.
