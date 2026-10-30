# RE-012 startup/CLI result: node #94

Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This is a bounded static evidence packet. No progress gate is advanced.

## Observations

| Measure | Result / denominator |
| --- | --- |
| Exact `node/src/hl_node.rs` relocated Location records | 53 |
| RIP LEA references to those Locations | 57 unique sites |
| Locations without a scanned LEA | 0 / 53 |
| Owning unwind ranges | 15 / 121,299 decoded FDEs; not function coverage |
| Explicit CLI/startup candidates | 16 |
| Candidates with one qualifying scoped anchor and exact pointer/length pair | 10 / 16 |
| Unresolved candidates | 6 / 16 |
| Additional diagnostic candidates | 4 bound / 5 examined |
| String-anchored side-effect markers | 7 write flags + 4 diagnostic/template markers |
| Selected direct call among scoped FDEs | 1 |
| Proven service-to-port assignments | 0 |

All owning ranges are below. Each Location has one owning FDE in this
artifact, although four Locations have two LEA sites in that owner. Full
Location addresses, source lines/columns, LEA sites and raw CIE/FDE records
are retained in the JSON and excerpts.

| FDE start | Exclusive end | Locations | LEA sites |
| --- | --- | --- | --- |
| `0x225dd90` | `0x225ddf8` | 1 | 1 |
| `0x2271d00` | `0x2272c74` | 6 | 7 |
| `0x2272c80` | `0x2275a07` | 3 | 4 |
| `0x2275a10` | `0x227a0db` | 5 | 6 |
| `0x22ae8a0` | `0x22b107c` | 8 | 9 |
| `0x4546ac0` | `0x4546b98` | 2 | 2 |
| `0x4546ba0` | `0x4546c51` | 1 | 1 |
| `0x4578bd0` | `0x4578e2a` | 3 | 3 |
| `0x4579310` | `0x457acef` | 2 | 2 |
| `0x4583030` | `0x4583f52` | 17 | 17 |
| `0x4583f60` | `0x4583fb6` | 1 | 1 |
| `0x4584030` | `0x4584136` | 1 | 1 |
| `0x4584140` | `0x4584172` | 1 | 1 |
| `0x4584180` | `0x45841f7` | 1 | 1 |
| `0x4584200` | `0x4584306` | 1 | 1 |

| Bound candidate | Literal VA | Example scoped LEA VA | Owning FDE start |
| --- | --- | --- | --- |
| `chain` | `0x6f6148` | `0x4578be7` | `0x4578bd0` |
| `serve-evm-rpc` | `0x6f6251` | `0x457a11a` | `0x4579310` |
| `serve-info` | `0x6f625e` | `0x457ac10` | `0x4579310` |
| `write-trades` | `0x6f6183` | `0x457937f` | `0x4579310` |
| `write-fills` | `0x6f618f` | `0x457955f` | `0x4579310` |
| `write-raw-book-diffs` | `0x6f619a` | `0x45796ef` | `0x4579310` |
| `write-order-statuses` | `0x6f61ae` | `0x4579830` | `0x4579310` |
| `write-misc-events` | `0x6f61c2` | `0x457996d` | `0x4579310` |
| `write-hip3-oracle-updates` | `0x6f61d3` | `0x4579a9b` | `0x4579310` |
| `write-system-and-core-writer-actions` | `0x6f61ec` | `0x4579ba8` | `0x4579310` |

`chain` has 73 `.rodata` occurrences; only one qualifies in this scope. Each
example above is immediately followed by `mov $length,%edx`, corroborating
the candidate boundary despite concatenated string pools.

| Unresolved candidate | Observation |
| --- | --- |
| `data-dir` | Exact bytes absent from `.rodata`; no absence-of-feature claim |
| `run-validator` | Exact bytes absent from `.rodata`; no absence-of-feature claim |
| `serve-eth-rpc` | One `.rodata` occurrence, no qualifying scoped anchor |
| `check-reachability` | One `.rodata` occurrence, no qualifying scoped anchor |
| `delegate` | 26 substring occurrences, no qualifying scoped anchor; `undelegate` is insufficient |
| `override_gossip_config.json` | One `.rodata` occurrence, no qualifying scoped anchor |

The selected direct call at `0x22aef61`, bytes `e8 9a 2d fc ff`, belongs to
`0x22ae8a0..0x22b107c` and lands at FDE start `0x2271d00`. Both ranges own
`hl_node.rs` Locations. The destination also contains scoped anchors for
`check_reachability_firewall_ips` at LEA `0x2271f1e` and
`failed to load firewall ips` at `0x22722c1`. This establishes one static edge,
not a complete startup task graph or proof that the call executes.

`@@ archiving data to s3` occurs inside the NUL-bounded buffer at `0x1f4100`,
loaded by LEA `0x2275be0` in `0x2275a10..0x227a0db`. The command-template
fragment `timeout 3 nc -zv ` is inside the buffer at `0x1ee597`, loaded at
`0x2272b28` in `0x2271d00..0x2272c74`. These and the seven `write-*` flags
identify possible external/write effects. They do not establish successful
writes, process spawning, network traffic, destinations, permissions or
runtime conditions. The non-validator bootstrap diagnostic is present but
has no qualifying scoped anchor and remains unresolved.

At `0x227261e`, instruction bytes `c7 83 4c 07 00 00 a1 0f a4 0f` encode a
32-bit immediate store of `0x0fa40fa1`; its little-endian u16 halves are
4001 and 4004. It is co-located with the reachability markers. This is only a
numeric observation. The proposed gossip/stream/consensus assignments for
4001..4006 all remain unresolved; 4002, 4003, 4005 and 4006 have no retained
numeric observation here. No exhaustive search for every port encoding is
claimed.

## Inferences and remaining gaps

The string/Location co-location supports CLI-option and reachability/archive
interpretations of these ranges. It does not establish CLI syntax, defaults,
accepted values, flag interactions, dispatch discriminants, callback identity,
gossip configuration loading, port roles or task-launch order. Reference
constants are not promoted to facts. Instruction decoding is linear from
unwind starts; full CFG analysis, dynamic reachability and calls through
registers/relocation slots remain outside this bounded packet.
Names such as “parser”, “orchestrator” and “unwrap” in the reference are
interpretations, not recovered debug symbols.

No TCP frame claims, InfoRequest remapping, node #115/visor claims, recovered
Rust, runtime equivalence, helper/data closure or complete RE-012 acceptance
are asserted. The packet fulfills the stated inventory question with explicit
unresolved entries; the broader RE-012 gate remains unfinished.

## Validation

Observed on 2026-10-30, Python 3.13.5 / GNU binutils 2.44:

| Command/check | Actual result |
| --- | --- |
| `python3 tools/hl_node_startup_inventory.py --out research/work-items/hl-node-startup-inventory-94/` | PASS; JSON and excerpts generated from the pinned artifact |
| `python3 -m unittest tests.test_hl_node_startup_inventory -v` | PASS: 31 tests, no skips; includes all reported instruction starts and all 15 FDE ranges checked with native tools |
| `python3 research/work-items/hl-node-startup-inventory-94/verify.py` | PASS: exact manifest, digest, pinned counts and byte-identical regeneration |
| `python3 -O -B research/work-items/hl-node-startup-inventory-94/verify.py` | PASS; checks do not depend on `assert` |
| Two directory regenerations with `PYTHONHASHSEED=0/97` | PASS: both generated files byte-identical |
| `make doctor` | PASS: static analysis ready; no Ghidra/Java and no exact-rebuild evidence |
| `make verify test catalogue-check` | Stops at verify: retained artifact digests and signatures pass, then missing `references/can1357-hl/bin/hl-node-mainnet-new` prevents pinned-pair comparison |
| `make test` separately, final rerun | 386 tests run, 20 errors in existing reference-dependent suites; all 31 startup tests pass |
| `make catalogue-check` separately | FAIL: reports stale `research/catalogue/components.json` when generating against the empty reference directory; no catalogue rewritten |
| `make reproduce` | FAIL at artifact verification's missing pinned reference, before inventory/literal regeneration |
| `git diff --check` | PASS |

The 20 full-suite errors concern missing can1357 consensus, exchange,
InfoRequest and database files (plus a subprocess failure from the same
missing exchange input). These failures are not presented as repository-wide
success. The checkout's missing submodules were not installed, repinned or
replaced. Initial and final raw check logs remain under ignored
`work/hl-node-startup/`, including the first full test run made before this
packet's manifest existed; that run also had two missing-manifest errors,
resolved in the final rerun.

Generated JSON SHA-256:
`58ea0049b4d1118fcb981e385549d792990589998f3d5b7e0c9a3aaafee963e8`.
Raw excerpts SHA-256:
`6ce6f329f37b2e1d0d41eb360fcff4b40b5b2ba6df5e758d3628b0e1b999e4be`.
No target execution or hosted CI/container result is claimed.

## Command outcomes (contribution tree)

Packet authored against hyperliquid-source `1f8c67c63ca4794c9689235471c60297f8a5c985` with pinned LFS inputs.

- `python3 tools/hl_node_startup_inventory.py --out research/work-items/hl-node-startup-inventory-94/`: exit 0
- `python3 -m unittest tests.test_hl_node_startup_inventory -v`: 31 tests, OK
- `python3 research/work-items/hl-node-startup-inventory-94/verify.py`: PASS
- `make verify`: exit 0
- `make test`: 462 tests, OK (exit 0)
- `make catalogue-check`: exit 0

