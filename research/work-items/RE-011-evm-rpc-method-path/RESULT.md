# RE-011 result

Packet: `research/work-items/RE-011-evm-rpc-method-path/`.  
Static evidence for node **#94** SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.  
Dependency comparison only also binds node **#115** SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.  
No new claims beyond the packet README and JSON; this file records check outcomes for the contribution run.

## Observations (summary)

- All 26 `eth_*` strings from the inferred reference `build_route_table()` have pointer LEAs in #94 FDE `0x27ab650..0x27abc18`, each followed by an observed matching byte length and a rel32 call to an FDE start (details in `evm-rpc-method-path.json`; selected sites checked with objdump in tests).
- Router Location FDE `0x20266a0..0x2027608` calls that string-bearing FDE at `0x20267ad` (`e8 9e 4e 78 00`). Router Location FDE `0x202ec80..0x20312c2` calls `0x2027610..0x2028519` at `0x202f4d9` and `0x2030034`. The packet records 42 scoped `evm_rpc/` Location records and the #94/#115 revm/reth/evm_rpc path observations.

## Inferences and unresolved

The 26-string FDE is a route-table construction **candidate**. Path differences suggest dependency sourcing/fork layout drift; they do not establish fork revisions or patches. No verified dispatcher/handler edge, async/indirect call recovery, implementation, behavior, or binary-equivalence claim. **No gate change**; `research/progress.json` unchanged.

## Commands and exit codes (contribution tree)

Run from the repository root on Linux x86_64 with the pinned LFS artifacts present:

| Command | Exit | Notes |
| --- | ---: | --- |
| `make doctor` | 0 | `analysis_ready: true`; exact rebuild still false |
| `python3 tools/evm_rpc_method_path.py --out research/work-items/RE-011-evm-rpc-method-path/` | 0 | |
| `python3 -m unittest tests.test_evm_rpc_method_path -v` | 0 | 8 tests |
| `python3 research/work-items/RE-011-evm-rpc-method-path/verify.py` | 0 | manifest + regeneration |
| `PYTHONHASHSEED=7` regeneration + `cmp` | 0 | |
| `make catalogue-check` | 0 | |
| `make verify` | 0 | artifact hashes/signatures and import verification with LFS inputs present |
| `make test` | 0 | full offline suite |

Captured binaries were not executed. Network was not used for evidence generation.
