# RE-004: node #115 assets, fixed-point quantities (`qtys`), PDI, and perp/spot metadata integration

- Component ID: `assets` (`RE-004`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: observation for all ELF section/FDE bounds, `.rodata` constants, `.rela.dyn` panic `Location` bindings, and decoded x86-64 instructions; inference for Rust type names (`Pdi`, `PerpAsset`, `SpotAsset`, `Px`, `Sz`, `Szi`, `Ntl`, `Ntli`, `Wei`, `Usdc`, `PerpMeta`, `SpotMeta`). No full-component acceptance gate is claimed by this packet alone.
- Implementation path: `src/node115-assets` (integrates 13 Cargo-packaged `RE-004` micro-crates plus binary-grounded `pdi`, `qtys`, `meta`, and `wire_qty` modules).

## Evidence (node #115 static observations)

All virtual addresses below are verified directly against `artifacts/node/115/hl-node` by `tests/test_assets_qtys_meta_115.py` and recorded with SHA-256 digests in `evidence.json`:

| VA / Range | Source diagnostic anchor | Observed #115 semantics |
| --- | --- | --- |
| `.rodata` `0x5ed748..0x5ed7e8` | referenced by `0x22e48d2`, `0x22f5e7b`, `0x22f5f04` | 20-entry `f64` powers-of-10 table (`10^0 ..= 10^19`, little-endian IEEE-754) |
| `0x22b3160` (`pdi` range builder) | `l1/src/asset/pdi.rs:32:14` | Encodes `perp_id = pdi * 10_000 + local_index` (`mov $0x2710, %eax; mulq 0x50(%rsi); jo; add; cmp; jb`) |
| `0x22e4810` (`perp_meta` lookup & price scale) | `l1/src/perp_meta.rs:163:38`, `287:28` | Splits `perp_id` by `10_000` (reciprocal `0x346dc5d63886594b >> 11`, `imul $0x2710`), verifies `pdi == meta+0x50`, `local < meta+0x10`, reads `sz_decimals` byte at `universe[local]+0x1d` (stride `0x20`), enforces `< 7` (`cmp $0x7, %rax; jae`), scales price by `1 / POW10_F64[6 - sz_decimals]` |
| `0x22f5de0` (`spot_meta` dual price scale) | `l1/src/spot_meta.rs:119:33`, `590:25`, `1055:9` | Zero raw price short-circuits to `0.0` before metadata lookup; nonzero bounds-checks `pair < universe.len()`, loads `(base, quote)` at stride `0x20`, bounds-checks both tokens against `tokens.len()`, reads `quote.wei_decimals` (`+0x49`) and `base.sz_decimals` (`+0x48`, stride `0x158`), checks `quote.wei_decimals >= base.sz_decimals` (`sub; jb`), divides by `POW10_F64[diff]` |
| `0x294bcd0`, `0x29dfea0` | `l1/src/qtys/impl_ntl.rs:682:1` | Unsigned `Ntl` saturating add: on carry (`jb`), calls overflow reporter GOT slot `0x64e4ea8` and saturates to `u64::MAX` (`0xffffffffffffffff`) |
| `0x2a83960` | `l1/src/qtys/impl_ntl.rs:683:1` | Signed `Ntli` saturating add: on signed overflow (`jo`), calls `0x64e4ea8` and saturates via `sar 63; xor 0x8000000000000000; cmovo`; also computes `/ 10_000` via `0x346dc5d63886594b >> 11` |
| `0x22e6390` | `l1/src/qtys/impl_wei.rs:6:1`, `qtys/mod.rs:835:1` | Bounded spot hold check `hold + delta <= total` without carry (`lea; cmp; setbe; cmp; jb`) |
| `0x22f6d50` | `l1/src/qtys/impl_sz.rs:39:1`, `qtys/mod.rs:848:1` | Signed position delta: rejects `< 0` (`test; js`), checks `add; jo`, classifies sign `{pos: 0, neg: 1, zero: 2}` to detect nonzero sign change |

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 -m unittest tests.test_assets_qtys_meta_115
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/assets-fees-book \
  cargo test --manifest-path src/node115-assets/Cargo.toml
(cd research/work-items/RE-004-node115-assets-qtys-meta && sha256sum -c MANIFEST.sha256)
```

## Limitations

- `src/node115-assets` is an integrated library crate combining 13 Cargo-packaged `RE-004` micro-crates and the binary-grounded `pdi`, `qtys`, `meta`, and `wire_qty` modules. It does not claim full ELF ABI equivalence or whole-component gate closure yet; standalone `lib.rs`-only leaf directories (`node115-price-core`, `node115-spot-decimal`, `node115-signed-bound-kernel`, `node115-perp-tier-selector`, `node115-quantity-change`, `node115-mixed-tuple-threshold`, `node115-decimal96-normalize`) remain untouched so existing hash-locked tests remain green.
