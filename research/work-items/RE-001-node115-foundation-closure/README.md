# RE-001: Node #115 `foundation` (`base/src/*.rs`) Full-Scope Closure

Component: `foundation` (`base/*`).
Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`), SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Summary

Exhaustively authenticates the complete node #115 `base` (`foundation`) inventory directly
against `artifacts/node/115/hl-node`, `work/index/node-115-fde.tsv`, and
`research/components.json`:

- **33/33 `base/src/*.rs` source files** observed in node #115 `.rodata`, mapped 1-to-1 to
  `src/node115-base/src/*` (`api_url.rs`, `bucket_guard.rs`, `build_mode.rs`, `cid.rs`,
  `guards.rs`, `l1_map.rs`, `lock_id.rs`, `log_settings.rs`, `runtime_utils.rs`,
  `short_string.rs`, `time.rs`) plus all 48 registered `foundation` `implementation_paths`.
- **247/247 `.data.rel.ro` `panic::Location` structs** (`247` referenced in `.text`, `0` unreferenced).
- **839/839 unique referencing `.text` FDEs (`1,675,149 B`)**.
- **9 `.rodata` string literal anchors** and **6 `.text` instruction anchors** verified against raw binary bytes.
- **Honest compiled-byte status (`identity_gate_satisfied: false`)**:
  - `RE-001-node115-foundation-byte-matches`: 69 first-party `base` FDEs (`9,450 B`, consolidated into Wave 4 `research/byte-windows.json`).
  - `RE-001-node115-foundation-l1-map-byte-matches`: 79 first-party `base/src/l1_map/entry.rs` business-logic FDEs (`19,901 B`, `92.58%` raw-equal, Wave-5 ready).
  - Combined live-compiled `foundation` FDEs across Wave 4 + `l1_map` remain a strict subset of full `base` code/data identity, so `identity` remains strictly `false`.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-foundation-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_foundation_closure_115 -v
```
