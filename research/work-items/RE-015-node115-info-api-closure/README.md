# RE-015: Node #115 `info-api` Full-Scope Closure (`info_server/src/*.rs`)

- **Target**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `info-api` (`info_server/*`).
- **Closure Status**: Full static inventory & behavioral closure ready for joint `mapped`/`built`/`behavior` gate review (`identity` remains `false`).

## Complete Inventory Authenticated Directly Against Node #115

- **Source files**: **7/7** `info_server/src/*.rs` files (exact match with `research/imported/hl-node-115.inventory.json`).
- **Panic `Location` structs**: **43/43** `.data.rel.ro` entries (0 unreferenced).
- **Referencing `.text` FDEs**: **131/131** exact FDEs totaling **131,304 B** verified against `work/index/node-115-fde.tsv`.
- **`InfoRequest` wire variants**: **55/55** authenticated directly from `.data.rel.ro` `@0x643a9e0` via `.rela.dyn` (`fileSnapshot` through `userStarState`), matching `0x2744200..0x2744bfa` (`2,554 B`, already matched in Wave 3 `research/byte-windows.json`).
- **Compiled-byte identity already landed for `info-api`**:
  - `node115-fp-w3-enum-info-request-json-2744200` (`0x2744200..0x2744bfa`, `2,554 B`) plus `RE-015-node115-stream-f-byte-matches` and micro-crate proofs (`node115-position-integer`, `node115-risk-candidate-scan`, `node115-replica-response-json`, `node115-json-string-scanner`, `node115-json-error-position`).

## 1-to-1 Source File Mapping

| Node #115 Source File | Locations | Implementation Paths |
| --- | ---: | --- |
| `info_server/src/abci_state_info_handler.rs` | 33 | `src/info-api/src/{request,router,response}.rs`, `src/node115-replica-response-json/src/lib.rs`, `src/node115-risk-candidate-scan/lib.rs` |
| `info_server/src/f_types/position.rs` | 2 | `src/info-api/src/position.rs`, `src/node115-position-integer/lib.rs`, `src/node115-risk-candidate-scan/lib.rs` |
| `info_server/src/handle_request.rs` | 3 | `src/info-api/src/{router,request}.rs`, `src/node115-json-string-scanner/lib.rs`, `src/node115-json-error-position/lib.rs` |
| `info_server/src/handler.rs` | 1 | `src/info-api/src/{router,lib}.rs` |
| `info_server/src/router.rs` | 1 | `src/info-api/src/router.rs` |
| `info_server/src/save_l4_snapshots.rs` | 2 | `src/info-api/src/{response,request}.rs` |
| `info_server/src/user_ip.rs` | 1 | `src/info-api/src/router.rs` |

## Verification

```bash
(cd research/work-items/RE-015-node115-info-api-closure && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-015-node115-info-api-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_info_api_closure_115 -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo +1.95.0 test --offline --locked --manifest-path src/info-api/Cargo.toml
```
