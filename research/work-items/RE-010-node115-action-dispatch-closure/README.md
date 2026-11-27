# RE-010: Node #115 Complete `action-dispatch` (Central Router & 92 Handler Entries) Full-Scope Closure

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `action-dispatch` (`l1/exchange/handlers/*`, `l1/exchange/impl_execute_action.rs` — Stream E2-B / `RE-010`).
- **Source-path ground truth**: Exhaustive `.rela.dyn` + `.data.rel.ro` scan confirms **0** `Location` structs match `l1/src/exchange/handlers/*` or `l1/src/exchange/impl_execute_action.rs` in node #115 because those split paths were inherited planning splits (`research/components.json`: `"Agent-created handler splits and central dispatch"`). Real node #115 dispatch lives in the 5 central dispatch/router FDEs, 92 router-dispatched handler FDEs, 5 shared admission helper FDEs, and 3 direct router-caller FDEs audited here.
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **105 strictly disjoint node #115 FDEs (`138,081 bytes`)** cross-checked 1-to-1 against `src/action-dispatch` (`router.rs` + `admission.rs` + all 10 registered sibling micro-crates, wired into `src/exchange` and `src/hl-node`).

## Complete Node #115 `action-dispatch` FDE Architecture

| Group | Unique FDEs | Bytes | Verified Anchors & Behavioral Reconstruction |
| --- | ---: | ---: | --- |
| Core central dispatch & tag-table FDEs (`0x2bda7c0`, `0x55f99b0`, `0x2bdb5b0`, `0x36c30f0`, `0x2bdbaa0`) | 5 | 12,249 | `src/action-dispatch/src/router.rs` (92-arm router, flag 50 mask `0x501d`, timer sentinel `0x3b9aca00`) + `src/action-dispatch/src/admission.rs` (timed router `0x55f99b0` special guards + tag classifier `0x36c30f0`) + 5 `.rodata` jump tables (`0x609f00`, `0x927b08`, `0x60a080`, `0x79afb0`, `0x60a360`) |
| All 92 router handler entry FDEs (`0x2c03970..0x2c1fd40`) | 92 | 116,432 | Every handler VA in `src/action-dispatch/src/router.rs` cross-checked against `action-dispatch-router-115/arms.tsv` and `work/index/node-115-fde.tsv`; includes all **10 exact 1,087-byte prior-key wrapper clones** (`admission::run_prior_key_wrapper`) + 92/92 shared admission call census (`action-dispatch-shared-admission-115`) |
| Shared admission helper FDEs (`0x2a8ab70`, `0x4717440`, `0x3ed25b0`, `0x2c202b0`, `0x2c206b0`) | 5 | 3,393 | Alias override, 20-byte key hasher, alias probe, and dual `0x1a2` admission checks called by 92/92 handlers |
| Direct central-router caller FDEs (`0x27048a0`, `0x2c69220`, `0x2c71250`) | 3 | 6,007 | All 5 direct `E8` call sites to `0x2bda7c0` (`action-dispatch-callsite-graph-115`) |
| **Combined (`action-dispatch`)** | **105** | **138,081** | **All 11 registered `action-dispatch` crates in `research/components.json` built & tested offline** |

## Honest Gate Status & Limitations

- **Mapped / Built / Behavior**: 0/0 split-path Locations verified; all 5 core dispatch FDEs, 92/92 router handler FDEs, 5/5 shared admission helpers, 3/3 direct router callers (`105` unique FDEs / `138,081 B`), 8 `.text` anchors, and 5 `.rodata` jump-table headers are machine-verified against node #115; `src/action-dispatch` (`#![forbid(unsafe_code)]`, 0 external deps, clippy `-D warnings` clean) and all 10 sibling micro-crates pass offline behavioral/boundary tests.
- **Identity**: `identity` remains `false`; compiled-byte proofs are tracked separately in `research/byte-windows.json` and compiled-byte packets (no whole-component byte identity is claimed here).
- **Static-only boundary**: The captured binary was inspected statically and was never executed or emulated.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-010-node115-action-dispatch-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_action_dispatch_closure_115 -v
(cd research/work-items/RE-010-node115-action-dispatch-closure && sha256sum -c MANIFEST.sha256)
(cd src/action-dispatch && cargo test --offline && cargo clippy --offline --all-targets -- -D warnings)
```
