# staking: jail-vote ordering and the NoVoter clone boundary in node 94

This packet makes the jail-vote median path reconstructible by recovering its previously stubbed long-sort ordering and scratch rules, and shows that the previously unexplained second-map clone reaches an uninhabited `NoVoter` diagnostic when a synthetic node contains an entry.

- Component ID: staking, validator jailing and vote lifecycle.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not implementation source.
- Claim status: observation for the fixed bytes, FDE extents, linked call sites and bounded instruction interpretation; inference for the intended meaning and reachability of the `NoVoter` map. Synthetic failures and unstated live behavior remain unresolved.
- Scope included and excluded: the six linked long-sort FDE windows, the second-map clone and its diagnostic helper. The prior jail-vote host is context at selected instruction sites only. The quorum, vote collection, short sort, jail mutation, real allocator and unwind implementation are not re-evaluated. Node #115 and execution of a captured binary are excluded.

## Reproduce

From the repository root, with Python 3 and the standard library:

```sh
python3 tools/staking_jail_vote_sort94.py --out research/work-items/staking-jail-vote-sort-94
python3 -m unittest tests.test_staking_jail_vote_sort94
(cd research/work-items/staking-jail-vote-sort-94 && sha256sum -c MANIFEST.sha256)
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For independent output comparisons, substitute a writable relative directory for the placeholder:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_jail_vote_sort94.py --out <tmp-dir>/first
PYTHONHASHSEED=391 TZ=Pacific/Honolulu python3 tools/staking_jail_vote_sort94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
```

The recorded environment was Python 3.12.3 on Linux x86-64. The generator first verifies the artifact digest, uses the repository ELF and FDE readers, excludes NOBITS from file-backed mappings, and reads relocations and instructions directly from the ELF. It invokes no external program and does not launch the captured node. `instructions.tsv`, `branches.tsv`, `functions.tsv`, `context.tsv`, `relocations.tsv`, `diagnostic.tsv`, `sort-cases.tsv`, `sort-witness.tsv`, `clone-cases.tsv`, `controls.tsv` and `summary.json` are generated; `MANIFEST.sha256` covers these and this README.

## Evidence

All addresses below are linked ELF virtual addresses. FDE ends and corresponding file offsets are in `functions.tsv`; each selected window is validated as file-backed executable data. FDE bounds are unwind-described ranges, not proof of a complete function census. The prior `staking-c-signer-jail-94` packet identifies the host and its vote-to-jail transition; this packet pins only the connecting bytes in `context.tsv` and does not claim the host as a new function.

| Role | FDE entry | Exclusive end | Bytes |
| --- | --- | --- | ---: |
| NoVoter diagnostic helper | `0x2f0a230` | `0x2f0a243` | 19 |
| Sort helper | `0x3384130` | `0x3384379` | 585 |
| Small partition | `0x338a9d0` | `0x338afae` | 1502 |
| Second-map clone | `0x33e7840` | `0x33e79e8` | 424 |
| Pivot | `0x3860f60` | `0x38610d8` | 376 |
| Sort driver | `0x38711a0` | `0x3871a14` | 2164 |
| Partition | `0x3885de0` | `0x3886527` | 1863 |
| Long-sort entry | `0x3bc24a0` | `0x3bc25e9` | 329 |

### Connection to the jail transition

At `0x3993f08`, the previously studied host tests the second inner map's length at row `+0x28`; if nonzero it loads root `+0x18` and height `+0x20`, and calls the clone at `0x3993f25`. Later, the host's comparison at `0x3994b0a` selects the existing short sort for fewer than 21 rows and the indirect call at `0x3994b6d` for 21 or more. The latter uses RELATIVE relocation slot `0x5776250` to enter `0x3bc24a0`. These host instructions establish connections, not a fresh end-to-end evaluation of the host.

### Long-sort ordering and scratch

The selected code moves 24-byte rows. For the tested rows, the independent ordering rule is signed 32-bit date, unsigned 32-bit seconds, unsigned 32-bit fraction, and unsigned 64-bit weight at `+0x10`, in that order. The four bytes at `+0x0c` are carried with the row and are not part of that rule. `sort-witness.tsv` records complete before/after rows, including ties with distinct padding. All 142 synthetic fixtures matched the independently written stable ordering, including signed-date and unsigned-weight controls; this establishes stability for these fixtures, not for all possible inputs.

The entry computes `wanted = max(min(n, 333333), n - floor(n / 2))` in rows. It uses a 170-row stack buffer when `wanted < 171`. Otherwise it requests `24 * max(wanted, 48)` bytes and frees the same size after normal completion. The following are direct controls; oversized inputs stop at the injected allocator and are not actually allocated:

| Synthetic count | Observed allocation or guard |
| ---: | --- |
| 170 | stack scratch, no allocation |
| 171 | 4104-byte allocation and normal free |
| 333333 and 666666 | injected allocation failure after a 7999992-byte request |
| 666667 | injected allocation failure after an 8000016-byte request |
| `2^64 - 1` | capacity-failure boundary before any allocation |

The driver calls the partition through RELATIVE slot `0x5775fd0`; the partition calls the pivot or, below 33 rows, the small partition. Direct small-partition controls with two or more rows trap at `0x338af8d` when scratch has fewer than `n + 16` rows; zero and one row bypass that check. These controls do not show that the enclosing host can pass insufficient scratch.

### Second-map clone

The clone treats node count `+0x8e` as a 16-bit word. Empty synthetic nodes use leaf allocations of `0x90` bytes and internal allocations of `0xf0` bytes; for the tested empty chains the returned height, count and child backlinks match the source shape. A synthetic nonzero node count on either the leaf or an ancestor takes one of the calls at `0x33e799d` and `0x33e79b4` to `0x2f0a230`. That helper loads the 71-byte diagnostic at `0x57ada0`, including the type name `hard_quorum_policy::NoVoter`, and calls the failure slot at `0x2f0a23d`. All 21 nonempty cases across heights zero through five reach that exact modeled boundary; the six empty-chain controls return normally. The ancestor chains are deliberately synthetic and can violate normal B-tree invariants.

The literal supports the inference that each second-map entry would require an uninhabited type, explaining the empty second map in the earlier jail-vote fixtures. Whether that type is the key or the value is not established here. These observations do not prove every deserializer or producer preserves the invariant, nor that a live or malformed chain state can reach the diagnostic. With consistent length metadata the host bypasses the clone when the second map length is zero, so the direct empty-clone controls are not asserted to be host-reachable.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No compiler, linker, raw-byte or normalized-byte comparison is claimed. The bounded Python interpreter is adapted from the repository's MIT-licensed staking analysis, and the independent row-order rule is a test oracle. Allocator, free, memory-copy and failure operations are checked hooks. No captured node or visor is launched. No helper, relocation, data or whole-ELF closure is claimed beyond the listed windows and slots.

## Results and limitations

- The eight selected FDE windows total 7262 bytes and 1958 linearly decoded instruction rows. The normal sort and clone fixtures reach 1777 instruction starts; both edges are observed at 146 of 212 conditional sites. These are packet-local counts, not a component denominator.
- The generator compares 142 sort fixtures and 27 clone fixtures to their stated rules, and records 28 separate controls. Three instruction changes are detected: scratch selection, signed-date comparison and the clone's nonempty branch. A modeled stop is not a prediction of native execution.
- The focused unittest suite contains 18 tests with no skips. It includes a wrong digest, changed function and diagnostic bytes, duplicate or altered relocations, non-file-backed addresses, allocation failures, short scratch and changed instruction controls.
- The interpreter stops at modeled failure boundaries. Actual allocator cleanup, panic and unwind behavior, the short-sort implementation, the host's remaining paths, malformed real trees, all possible input vectors and live validator behavior remain open. No full-component progress gate is requested.

Next question: independently reconstruct the 24-byte ordering and weighted-median consumer in Rust, and establish from the real state readers whether any second-map entry can ever be produced.
