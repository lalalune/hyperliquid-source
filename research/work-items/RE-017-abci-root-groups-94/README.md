# RE-017: grouped state-root inputs and the reloaded freeze field

The three grouped app-hash inputs serialize 39 ordered state-field pointers, including the reloader's cleared freeze-height slot as field 1 of group 39; a reconstruction can now preserve those groups' ordering, the selected option and enum encodings, and their error exits, subject to the unresolved identity of the reloaded and hashed objects.

- Component ID: `abci`, RE-017, bounded state-loader-to-root-input question.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; unlicensed reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation was copied.
- Claim status: exact ELF observations, conditional dataflow inference and unresolved runtime behavior are separated below. Synthetic examples are not node executions.
- Scope included and excluded: six previously unclaimed group serializers and eight selected child FDE ranges, plus narrowly selected prior builder, closure, keyed-serializer, encoder and reload instructions as connectivity context. The existing loader, its original GOT/call, hash builders and hash cores are not re-owned. The remaining 38 hash jobs, their nested serializers, action and block execution, node #115 and visor are outside this bounded result.

## Reproduce

Run from the repository root with CPython 3.12 or later and the node #94 artifact present:

```sh
python3 tools/abci_root_groups94.py --out research/work-items/RE-017-abci-root-groups-94
python3 -m unittest tests.test_abci_root_groups94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-017-abci-root-groups-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_root_groups94.py --out work/abci-roots-a
PYTHONHASHSEED=913 TZ=Pacific/Honolulu python3 tools/abci_root_groups94.py --out work/abci-roots-b
diff -r work/abci-roots-a work/abci-roots-b
```

The output directories for independent regeneration must initially be absent or empty. `evidence.json`, `fields.tsv`, `key-context.tsv`, `enums.tsv`, `branches.tsv`, `helper-returns.tsv`, `closure-exits.tsv` and `prefixes.tsv` are generated; the manifest covers those files and this README. The generator checks the full artifact SHA-256 before parsing, uses the repository's `tools/elf_index.py` and `tools/fde_extents.py`, excludes NOBITS sections from VA-to-file translation, and accepts a VA interval only if it is uniquely allocated and file-backed. It decodes only specified x86 byte forms and starts no external program. Development used Python 3.12.3 on Linux x86-64; GNU objdump 2.42 was used for human inspection only. The tool, tests and fixtures do not execute the artifact, access the network, or use time, random values, host paths or binutils output.

## Evidence

All addresses are ELF link-time virtual addresses; file offsets are separate. For example the reload clear at VA `0x327280f` maps to file offset `0x327180f`. Ends are exclusive. `evidence.json` binds each of the 14 selected extents to its CIE/FDE, matching unwind-index record, file offset and full raw-byte SHA-256; their combined length is 9030 bytes. An FDE is an unwind range, not proof of every function boundary or a whole-component denominator. No normalization mask is applied.

The prior [state link](../RE-017-abci-state-link-94/README.md) establishes the Location-bearing load; [round clock](../staking-round-clock-94/README.md) covers the reload and names its cleared field; [app-hash builder](../RE-009-app-hash-builder-94/README.md) establishes the hash jobs and leaves their serializer contents open. Here, only the following selected new extents are studied. Encoder targets and unlisted child functions are boundaries.

| Role | Low-lane entry | Shared-lane entry |
| --- | --- | --- |
| Group 38, 15 fields | `0x1e5e450` | `0x4446d90` |
| Group 39, 16 fields | `0x1e5ed40` | `0x44465a0` |
| Group 40, 8 fields | `0x1e5d9b0` | `0x4445a70` |
| Option with tag 1 and 64-bit payload | `0x1e0fcc0` | `0x43f69d0` |
| One-byte Boolean-shaped value | `0x1e0fed0` | `0x43f94f0` |
| 64-bit integer forwarding | `0x1e0f310` | `0x43f4700` |
| Option with tag 2 and delegated other case | `0x1e10760` | `0x43f4840` |

### From captures to serializer entries

The existing low builder `0x2755dc0` builds the 15-, 16- and 8-pointer boxes and binds them to rows 38, 39 and 40 of the table at `0x56bda38`. The shared-table builders `0x4d7c910` and `0x4d7e8c0` bind the corresponding boxes to the table at `0x57446e8`. For each row `prior_context_links` checks its data store, table address, file-backed table size, type-8 symbol-zero RELATIVE relocation, thunk and closure-to-serializer call. There are nine builder/row links; the two shared builders use the same three closure bodies. For each builder, `prior_builder_flow` also recognizes every instruction from the end of the last box capture through the row-40 data-pointer store: the only register written in that span is `rcx`. It checks the short allocation-size/null-test gaps and the saved box-register aliases separately. This supports register continuity along the selected path, assuming the intervening calls preserve the ABI's callee-saved registers; allocator effects, memory aliasing and runtime reachability are not established. These context windows do not claim any builder's complete behavior.

Let `E` be the captured builder input base. The low and secondary builders' 39 selected offsets agree exactly. Each of the primary builder's corresponding 39 offsets is `0xa80` larger; this is a recorded relationship for these fields only. `fields.tsv` identifies the builder behind each offset and records the shared primary offset separately. The six serializer entries read their box pointers in the listed order. A key in the next table is a literal used by a separate existing keyed serializer at the same low-base offset. Matching that key to the captured input is an inference about field naming; it is not proof of the primary builder's source-level type or of object identity across calls. Abbreviated literal keys retain their actual spelling.

| Group | Index | Low/secondary offset | Key context | Low callee or operation |
| --- | --- | --- | --- | --- |
| 38 | 0 | `0x8f2` | unresolved | `inline` |
| 38 | 1 | `0x3a98` | `last_hlp_cancel_time` | `0x1e11d20` |
| 38 | 2 | `0x3aa4` | `post_only_until_time` | `0x1e11d20` |
| 38 | 3 | `0x3988` | `post_only_until_height` | `0x1e0f310` |
| 38 | 4 | `0x39c0` | `prune_agent_idx` | `0x1e0f310` |
| 38 | 5 | `0x32a8` | `register_token_gas_auction` | `0x1e10760` |
| 38 | 6 | `0x37c0` | unresolved | `0x1e0cf80` |
| 38 | 7 | `0x37d0` | `funding_update_guard` | `0x1e0cf80` |
| 38 | 8 | `0x39c8` | `max_hlp_withdraw_fraction_per_day` | `0x1e0f450` |
| 38 | 9 | `0xbb0` | unresolved | `0x1e0ef60` |
| 38 | 10 | `0x38c0` | `book_empty_user_states_pruning_guard` | `0x1e0cf80` |
| 38 | 11 | `0x38b0` | `cancel_aggressive_orders_at_open_interest_cap_guard` | `0x1e0cf80` |
| 38 | 12 | `0x8f0` | `pdl` | `0x1e0fed0` |
| 38 | 13 | `0x3948` | `allowed_liquidators` | `0x1e12470` |
| 38 | 14 | `0x3960` | unresolved | `0x1e10e90` |
| 39 | 0 | `0x3980` | `max_order_distance_from_anchor` | `0x25aa640` |
| 39 | 1 | `0xb90` | `scheduled_freeze_height` | `0x1e0fcc0` |
| 39 | 2 | `0xba0` | `simulate_crash_height` | `0x1e0fcc0` |
| 39 | 3 | `0x3ac8` | `spot_disabled` | `0x1e0fed0` |
| 39 | 4 | `0x8b8` | `qus` | `0x1e12470` |
| 39 | 5 | `0x38f8` | `begin_block_logic_guard` | `0x1e0cf80` |
| 39 | 6 | `0x3ac9` | `evm_enabled` | `0x1e0fed0` |
| 39 | 7 | `0x31a8` | `partial_liquidation_cooldown` | `0x1e10960` |
| 39 | 8 | `0x32e8` | `perp_deploy_gas_auction` | `0x1e10760` |
| 39 | 9 | `0x3328` | `spot_pair_deploy_gas_auction` | `0x1e10760` |
| 39 | 10 | `0x3908` | unresolved | `0x1e11f80` |
| 39 | 11 | `0x7a0` | unresolved | `0x1e0ddc0` |
| 39 | 12 | `0x3938` | `hip3_stale_mark_px_guard` | `0x1e0cf80` |
| 39 | 13 | `0x3ab0` | `lvt` | `0x1e11d20` |
| 39 | 14 | `0x3aca` | `hip3_no_cross` | `0x1e0fed0` |
| 39 | 15 | `0x3a48` | unresolved | `0x1e0e190` |
| 40 | 0 | `0x3abc` | unresolved | `0x1dfca40` |
| 40 | 1 | `0x3acb` | `dex_abstraction_enabled` | `0x1e0fed0` |
| 40 | 2 | `0x3280` | unresolved | `0x233e900` |
| 40 | 3 | `0x8f1` | unresolved | `0x25aa7f0` |
| 40 | 4 | `0x3610` | unresolved | `0x23154f0` |
| 40 | 5 | `0x8e8` | `pmu` | `0x1e0f310` |
| 40 | 6 | `0x3acc` | unresolved | `0x1e0f820` |
| 40 | 7 | `0x3a68` | `pmn` | `0x1e0f310` |

In group 40, index 0 calls the displayed child only on the nonzero-tag arm; index 3 has three literal arms and the listed call is the representative tag-1 arm. `fields.tsv` also retains both lanes' load/call bytes and branch destinations. `key-context.tsv` retains all 27 same-offset load/key pairs, including exact literal bytes, lengths and file offsets. Twelve of the 39 positions have no keyed name established here.

### Reload, freeze option and prefix

The prior reload's normal-path setup at `0x3272799` uses `rsp+0x68` as the destination of a `0x3ae8`-byte copy. At `0x327280f` it stores a zero qword at `rsp+0xbf8`; `0x3272940` supplies `rsp+0x68` and `0x3ae8` for the result copy. The relative offset is therefore `0xb90`. These are fixed prior-boundary data-movement windows; the already owned indirect calls are not re-analysed here. The earlier round-clock packet associates this slot with `scheduled_freeze_height` and the code's normal return.

Separately, the low group-39 box captures `E+0xb90` at index 1, while the secondary shared builder captures `E+0xb90` and the primary shared builder captures `E+0x1610`. Group 39 passes that box entry to the respective selected option child. On its direct value path, the child compares the pointed-to dword with 1. Equal reads the qword at `+8` and calls the integer writer; unequal goes to a `0xc0` write, subject to buffer handling and errors. Index 2 uses the same child and the keyed context `simulate_crash_height`.

**Conditional inference:** if the successfully reloaded object, with the clear preserved, is the object subsequently passed as the low or secondary builder input, then this group writes nil for its freeze-height entry. The static evidence does not prove that those objects are identical, that this route is scheduled, that an intervening write cannot occur, or that a changed input necessarily produces a different final hash.

For a successful fresh writer, the low and shared encoder boundary windows show the group-39 prefix `dc0010` for its 16-element array, `cb` followed by the first field's eight bytes in big-endian order, then the selected option. Integer examples here are restricted to `0..65535`; this is the model's scope, not a claim that the binary rejects larger values. `prefixes.tsv` contains nine synthetic examples including both sides of 127/128 and 255/256, a 65535 case, a nonzero floating-point bit pattern, and non-one tags. They are calculated from pinned rules, with no captured target state and no target execution.

### Branches and error propagation

- Group 38 first reads a byte and indexes a relative jump table: entries 0, 1, 2 and 3 select `Local`, `Sandbox`, `Testnet` and `Mainnet`. No validity claim is made for other indices. Group 40 index 3 chooses `disabled` for byte 0, `reduceOnly` for byte 1, and `enabled` for other bytes on the selected branches. `enums.tsv` includes both lanes' actual table entries, literal addresses and bytes.
- The Boolean-shaped child reads a byte, ORs it with `0xc2`, and calls the pinned marker helper. For input bytes 0 and 1 the observed marker paths produce `c2` and `c3`. Invalid Boolean representations and the full helper contract remain out of scope. The other selected option child writes `c0` for tag 2 and delegates other tags; the delegated body remains a boundary. The integer child forwards its loaded qword to the corresponding encoder.
- The six parent array openers pass lengths 15, 16 and 8, respectively. Each checks the opener's result against 2; group 38's first label and group 39's first float do likewise. After a regular child, the parent compares the first result word with `0x8000000000000004`. `fields.tsv` records all 58 selected non-equal branches in groups 38 and 39; within each parent they share a failure join. `error_copies` records the join's result-copy bytes in all six parents.
- In both lanes, selected option, Boolean-shaped and tag-2 children initialize a sentinel register to `0x8000000000000000`. On the selected byte-buffer growth failure branch they write zero at result offset `+8`, `0x2600000003` at `+0x10`, and that sentinel as the first result word. The parent sees a word different from its `0x8000000000000004` success sentinel and copies the returned record. The 18 selected child terminal windows are in `helper-returns.tsv`; this states the local result stores, not the allocator contract.
- Group 40 additionally has distinct selected branches for its nil or child first item, the buffer preparation and third-child failure, the three-way label, the other children, and nil-buffer allocation. `branches.tsv` records these and the selected child option, marker, capacity and failure branches. An error exit does not establish atomic rollback of bytes already written. Finisher calls, allocator internals, unwinding and every unselected branch remain boundaries.

The six prior hash-closure contexts initialize the writer triple to `0, 1, 0` before calling these serializers. Each tests the returned first word against `0x8000000000000004`. Equality follows the pinned straight-line hash-state setup to the prior hash-update boundary. Inequality enters a separate result/cleanup path and, if the optional cleanup returns, prepares the length-bound `Result::unwrap()` diagnostic. `closure-exits.tsv` records the init, result test, both path windows, branch destination and diagnostic bytes. The closure and its hash-update and cleanup calls remain prior boundaries, and this does not prove any runtime invocation.

The tables record selected instruction forms, not a complete x86 decoder, whole-CFG reconstruction or dynamic branch-coverage census. Some child FDEs are shared by several field positions; the code does not assume their callers execute in every run.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Target execution, runtime fixtures, compiled comparison, normalization masks, helper/data closure and whole-ELF equivalence are not yet measured. The Python prefix routine is a deliberately bounded static model of the pinned successful writes; it is not a substitute for a target-grounded serializer comparison.

The focused suite passed 33 tests with zero skips. It includes a corrupted artifact digest, real FDE range and selected-body edits, a mutated RELATIVE entry, invalid/nonallocated/NOBITS/ambiguous file mappings, all 117 selected capture-displacement edits, all 58 regular failure-branch opcode and displacement edits, all eight group-38 table-entry edits, 27 key-literal edits, six sentinel edits, 18 child-result edits, mutations of all six prior closure branches and selected setup/diagnostic windows, three builder-flow instruction streams and allocator setups, the loader clear, and integer/model boundary controls. Private copy-on-write mappings keep the artifact unchanged.

## Results and limitations

The generated records contain 14 selected FDE extents, 9 prior builder/row links, 3 checked builder-flow slices, 117 capture stores, 78 serializer field rows for 39 positions, 27 keyed-context matches, 14 enum rows, 60 selected non-regular branch rows, 58 regular field-result branches, 6 openers, 6 sentinels, 6 parent result-copy windows, 18 child-result windows, 6 prior closure-outcome rows, and 9 synthetic prefixes. These are explicit selected-site counts, not ABCI coverage. Two independently generated outputs must match byte for byte. Artifact verification and catalogue checking are separate repository checks; no repository-wide test suite was run.

No progress gate is requested: the component's begin/action/end-block path and full state-root inputs remain open. Unknowns include remaining child encodings and keys, object provenance after reload, writer failure effects, job-runner ordering, all readers of the stored root and runtime reachability. Next question: can a previously unowned state-transfer path prove that the object copied by the reload reaches a specific hash-builder input without an intervening freeze-field write?
