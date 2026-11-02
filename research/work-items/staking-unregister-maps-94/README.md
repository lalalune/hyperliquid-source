# staking: validator unregister map removal in node 94

This packet identifies the unregister path's delegation guard and three ordered map operations, and recovers the profile and validator-state removal algorithms through predecessor substitution, sibling repair, and root collapse; a reconstruction can therefore remove a blocked validator's state row when the delegation guard permits, without treating its `delegations_blocked` byte as a separate clear operation.

- Component ID: `staking`, validator lifecycle and stake accounting.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred reference is a lead only; no unlicensed implementation is copied.
- Claim status: observations are byte pins, decoded operands, FDE records and results of the stated byte interpreter under its modeled boundaries. The staking field names and meaning of the enclosing action use earlier binary-backed packets. The caller slice is inspected statically and is not executed by this tool. Inferences and unresolved items are separated below.
- Scope included and excluded: twelve newly selected FDE ranges in `functions.tsv`; the state and profile map search, cursor, leaf and repair paths are interpreted. The first stake-map search stops at a pre-existing removal adapter. Small caller slices are context only: the enclosing action host, its authorization, the stake adapter, profile string destruction, allocator internals, runtime unwinding, and node #115 are not included. None of the twelve selected starts occurs in an existing work-item or in the two relevant open staking packets.

## Reproduce

Run from the repository root with Python 3.12.3 and the authenticated artifact. The generator checks the full SHA-256 before parsing or producing output, imports the shared ELF and CIE/FDE readers, and rejects SHT_NOBITS as a source of file bytes. The opcode decoder and interpreter are adapted from the MIT-licensed `tools/staking_stake_accounting.py`. They read captured bytes as data; they do not execute the artifact, invoke external programs, access the network, or use keys. The human-readable disassembly excerpt below was inspected with GNU objdump 2.42 and is not parsed or included in generated evidence.

```sh
python3 tools/artifacts.py verify
python3 tools/staking_unregister_maps94.py --out research/work-items/staking-unregister-maps-94
python3 -m unittest tests.test_staking_unregister_maps94
(cd research/work-items/staking-unregister-maps-94 && sha256sum -c MANIFEST.sha256)
```

The deterministic comparison used two distinct directories and a PATH containing Python but no binutils. Replace the placeholders with writable relative paths:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_unregister_maps94.py --out <tmp-dir-1>
PYTHONHASHSEED=917 TZ=Pacific/Honolulu python3 tools/staking_unregister_maps94.py --out <tmp-dir-2>
diff -r <tmp-dir-1> <tmp-dir-2>
```

`MANIFEST.sha256` covers this README and every generated evidence file. `summary.json` contains the input digest and the generated counts. `functions.tsv` records the FDE, file offset and whole-window digest for each selected range. FDE extents are unwind ranges, not a proof that all functions have been found or that every row in a range is reachable. `instructions.tsv` and `transfers.tsv` contain bytes and decoded operations, not objdump text; direct branches within a selected range must land on a decoded instruction start.

## Evidence

All addresses below are ELF virtual addresses; field offsets are relative to the `CStaking` base `S`. The earlier `staking-action-wire-94`, `staking-cstaking-state-wire-94` and `staking-stake-accounting-94` packets bind the unregister action niche and the names and locations of the staking fields. `context-pins.tsv` binds the caller slice below to bytes, and `status.tsv` extracts the refusal text through the ELF display table.

| Step in the context slice | Observation |
| --- | --- |
| Action selection | The word `0x8000000000000001` follows the pinned non-register, non-change branch to the unregister slice. The complete host is not interpreted here. |
| Delegation guard | A lookup reads the map rooted at `S+0x180`. A matching row with a nonzero first word produces `0x12f`, whose display text is `Cannot unregister validator with delegations`. A missing row or zero word proceeds. Earlier state evidence identifies that word as `total_delegated`. |
| Stake search | The caller passes `S+0x10` and the same 20-byte key to `0x33ab680`. The search returns a miss or passes its found node, height and slot to the excluded adapter. |
| Profile removal | The caller passes `S+0x150` and the key to `0x33ac190`. |
| State removal | The caller passes `S+0x278` and the key to `0x33aae60`, then writes success `0x186`. |

The caller's ownership and cleanup instructions between calls remain outside the interpreted path. In particular, this table does not prove transactional rollback if a removal or drop fails. It also does not say that the blocked flag is cleared in place: the entire state row is removed when its key is found, including when its flag byte is 1. Whether and how a later registration recreates the row remains open.

A short byte excerpt from the contextual slice is:

```text
399512a: 48 83 3b 00             cmp    qword ptr [rbx],0
3995133: 74 10                   je     0x3995145
399513a: 66 c7 45 00 2f 01       mov    word ptr [rbp],0x12f
39951f9: e8 62 5c a1 ff          call   0x33aae60
39951fe: 66 c7 45 00 86 01       mov    word ptr [rbp],0x186
```

### Selected closure and layout

| Range start | Role |
| --- | --- |
| `0x33ab680` | stake-map lookup up to its adapter boundary |
| `0x33ac190`, `0x2fda9d0`, `0x2fcb090` | profile lookup, cursor and leaf/ancestor removal |
| `0x2fa7210`, `0x2fac5e0` | profile left and right borrowing |
| `0x33aae60`, `0x2fda310`, `0x2fc6fc0` | validator-state lookup, cursor and leaf/ancestor removal |
| `0x2fa5d00`, `0x2fad5d0`, `0x2faded0` | validator-state left/right borrowing and merge |

The three maps compare 20-byte keys. State nodes have keys at `+0x8`, 28-byte values at `+0xe4`, parent at `+0`, edge index at `+0x218`, count at `+0x21a`, and internal child pointers at `+0x220`. Profile nodes have 88-byte values at `+0x8`, keys at `+0x3d0`, parent at `+0`, edge index at `+0x4ac`, count at `+0x4ae`, and internal child pointers at `+0x4b0`. `context-pins.tsv` anchors key bases, value stride, counts and root-free sizes; `instructions.tsv` retains the remaining operand bytes. The state and profile inner-node sizes used on root collapse are `0x280` and `0x510` respectively. The stake search uses a third layout and is checked only as far as the adapter boundary.

The state wrapper returns an absent result with byte `+0x18` equal to 2; the profile wrapper uses first word `0x8000000000000000` for absence. A present state fixture uses only valid boolean values 0 and 1 at that byte. These are output representation observations, not a claim about malformed state with other boolean bytes.

### Removal and repair decisions

A lookup hit at an internal node goes through the cursor's predecessor path: it removes the rightmost entry of the left subtree and substitutes the removed key and value into the internal slot. A leaf hit removes that slot directly. Each wrapper decrements its map count on a hit; a miss leaves it unchanged. The interpreter checks all retained keys, value bytes, parent pointers, edge indices, allocation ownership and map counts against a separately built in-order map model after each operation. It does not infer a tree's correctness solely from the return value.

| First repair condition | Observed action |
| --- | --- |
| Remaining leaf count above 4 | No sibling repair. |
| Underfull leaf without parent | Keep it as the root leaf. |
| Underfull leaf with parent edge above 0 | Choose the left sibling. |
| Underfull leaf at parent edge 0 | Choose the right sibling. |
| Old leaf count plus selected sibling count below 12 | Merge with the parent separator. |
| Old leaf count plus selected sibling count at least 12 | Borrow one row from that sibling. |

The sum uses the **pre-removal** count: a 5-row leaf with a 6-row sibling merges, while a 5-row leaf with a 7-row sibling borrows. On a merge, further underflow can propagate upward; an empty internal root is replaced by its first child and the old root is released. The test fixture's allocator hook checks the expected pointer and size for every release. `cases.tsv` gives the predicted and reached first repair for every single-removal case; `sequences.tsv` covers repeated deletion in ascending, descending and alternating orders. The 20 separate key-byte positions in `key-width.tsv` prevent a short comparison from passing merely because all keys share a prefix.

### Failure branches and inferences

`failure-controls.tsv` drives eight invalid borrow requests and two invalid state-merge requests directly into the selected helper entries. For both map layouts and both borrow directions, destination capacity and source underflow reach their respective failure boundary before either count is changed. The state merge likewise rejects an out-of-range tracked cursor and an over-capacity merge before those counts change. The malformed fixtures are explicit controls, not evidence that a valid on-chain tree reaches a panic. The table does not claim full rollback or model unwinding.

Inference: `S+0x150` and `S+0x278` are `validator_to_profile` and `validator_to_state`, and the selected path is validator unregister, from the earlier wire/state packets plus the pinned action and field use. The tool establishes that exact key/value bytes are removed; it does not validate the meaning of every time or profile byte. Fixture values are synthetic opaque bytes, and profile strings are not dereferenced. The existing stake adapter is deliberately a boundary: its target and semantics are not reanalysed, and a search hit is not counted as a completed stake removal.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No compiled Rust, normalized machine-code comparison, relocation equivalence, real allocator, real panic unwinding, target execution, or whole-node equivalence is claimed. The `memcmp`, `memmove` and `memcpy` hooks have dynamic-symbol bindings in `slots.tsv`; the deallocation slot is a relative relocation and is a checked fixture model. The interpreter follows selected instruction bytes and stops on an unmodeled call; it is not an independent CPU implementation or a substitute for an authorized target comparison.

## Results and limitations

- Twelve FDE ranges total 14,567 bytes and 2,945 decoded instruction rows. The named normal fixtures reach 2,561 rows; 87 of 183 conditional rows have both edges reached, and 25 have neither. `branches.tsv` gives the exact denominator and observed edges. Failure and mutation controls are reported separately and do not inflate that coverage.
- The generator checks 1,978 isolated state/profile removals, 867 stake lookup probes, and 240 key-position cases. Twelve deletion sequences perform 3,012 removals, including height-3 fixtures with 431 entries. All match the independent map model and structural invariants; `summary.json` records zero mismatches.
- Eight targeted instruction-byte mutations are detected, and ten malformed-helper fixtures reach the expected failure branch. The focused suite passes 31 tests with no skips, including corrupt input digest, changed context bytes, branch into an operand, non-file-backed and out-of-range addresses, both blocked values, root collapse, sibling boundaries, and the three-level sequences.
- Two runs under different hash seeds and time zones, with binutils absent from PATH, produced byte-identical evidence. The full repository test suite was not run. No full-scope component gate is requested.

Next question: after unregister has removed the state row, which separately selected registration path recreates it, and under what conditions does the new validator enter the active stake history? Establish failure behavior across the excluded host and ownership boundaries before treating this slice as a complete transaction.
