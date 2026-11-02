# staking: validator vote snapshot sorting in node 94

This packet closes the previously omitted long-sort step between validator vote snapshot filtering and tree construction: for the tested 32-byte rows it orders the 20-byte key stably, preserves the remaining bytes, and reveals the scratch allocation and failure boundaries needed to reconstruct that step.

- Component ID: staking, validator lifecycle and validator vote snapshots.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not implementation source.
- Claim status: observation for pinned ELF bytes, FDE records, modeled instruction results and explicitly stated synthetic inputs; inference for staking field and function roles inherited from earlier evidence. Unreached paths and behavior outside the hooks remain unresolved.
- Scope included and excluded: five non-overlapping FDE extents for the long-sort entry, driver, partition, small partition and pivot. The snapshot filter, short sorter, enclosing host and sorted-tree builder are context only; their already studied functions are not selected or re-evaluated. Live validator states, allocator internals, actual unwinding, a Rust implementation and node #115 are excluded.

## Reproduce

From the repository root with Python 3 and the standard library, using the authenticated artifact:

```sh
python3 tools/staking_vote_snapshot_sort94.py --out research/work-items/staking-vote-snapshot-sort-94
python3 -m unittest tests.test_staking_vote_snapshot_sort94
(cd research/work-items/staking-vote-snapshot-sort-94 && sha256sum -c MANIFEST.sha256)
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

To compare independent outputs, replace `<tmp-dir>` with a writable relative directory:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_vote_snapshot_sort94.py --out <tmp-dir>/first
PYTHONHASHSEED=391 TZ=Pacific/Honolulu python3 tools/staking_vote_snapshot_sort94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
```

The recorded runs used Python 3.12.3 on Linux x86-64. GNU objdump 2.42 was used for focused human inspection only. The generator verifies the full digest first, imports `tools/elf_index.py` and `tools/fde_extents.py`, excludes NOBITS from file mappings, reads relocation records directly, and interprets a bounded x86 subset over synthetic memory. It calls no external program and does not execute the captured binary. The same generator and focused tests were run with binutils absent from `PATH`; the two generated directories compared byte for byte. The generated TSV and JSON files are covered with this README by `MANIFEST.sha256`.

## Evidence

All addresses are linked ELF virtual addresses; the selected file offsets and unmasked body hashes are in `functions.tsv`. Ends are exclusive unwind FDE ends. Calls and relocation slots corroborate selected entries, but an FDE is not proof of a complete function census. Linear decode covers the selected windows only, and branch targets inside a selected window are checked against decoded instruction starts. Raw instruction bytes, conditional edges and direct or indirect calls are in `instructions.tsv`, `branches.tsv` and `calls.tsv`.

| Selected role | Entry | Exclusive FDE end | Bytes |
| --- | --- | --- | ---: |
| Long-sort entry | `0x3bc2240` | `0x3bc2367` | 295 |
| Driver | `0x38638e0` | `0x3863fb1` | 1745 |
| Partition | `0x3885850` | `0x3885ddb` | 1419 |
| Small partition | `0x338b7f0` | `0x338be92` | 1698 |
| Pivot | `0x38612f0` | `0x38613b7` | 199 |

### Connection and selector

The earlier `staking-vote-snapshot-filter-94` packet identifies the producer's 32-byte rows and a sorted-vector tree builder, but explicitly excludes their intervening sort. The present packet binds that gap using the fixed selector instructions in `anchors.tsv` and the actual RELATIVE relocation records in `relocations.tsv`. The earlier packet's field names are used as context, not re-proved here.

| Row count or condition | Observed edge |
| --- | --- |
| 0 | Empty-vector branch; the selected sort is not called. |
| 1 | The host bypasses both sorting calls. |
| 2 through 20 | The host calls the separately studied short sorter. |
| At least 21 | The host calls through slot `0x5775ca0`, whose relocation resolves to `0x3bc2240`. |
| Driver calls partition | The partition slot `0x5775f00` resolves to `0x3885850`. That function calls the small partition for its subproblem below 33 rows and can call the pivot for larger subproblems. |
| Sorted rows ready | The host advances its end pointer by `32 * count` and calls the previously studied builder. |

The long-sort input is a pointer and count. The compare import is `memcmp`, and every interpreted comparison hook checks a width of 20 bytes. The fixtures treat bytes `0..20` as a key and bytes `20..32` as payload. `witnesses.tsv` preserves complete key and payload values before and after representative runs. Each result is compared byte for byte with a separately written stable sort over the 20-byte key; the complete input rows, including the four intermediate bytes and the last eight bytes, remain attached to their keys. Equal-key input order is preserved in every stated case, including the 256 two-value patterns and 120 prefix permutations. These are bounded synthetic results, not proof for every possible input or evidence that duplicate validator keys arise in a valid source tree.

### Allocation, partition and failure branches

The entry computes `wanted = max(min(n, 250000), n - floor(n / 2))` in rows. For `wanted <= 128`, it passes a 128-row stack buffer. For larger values it requests `32 * max(wanted, 48)` bytes and frees that scratch allocation after a normal return. The multiplication and size guard precedes the allocation. The saved bytes and `capacity.tsv` separate the arithmetic guard from an injected null allocation:

| Synthetic input or injected condition | Observed boundary |
| --- | --- |
| 128 rows | Stack scratch; no allocation hook. |
| 129 rows | A 4,128-byte allocation and matching free, even for the tested already sorted input. |
| 250,000 through 500,000 rows | With allocation forced to fail, an 8,000,000-byte request reaches the null-allocation failure call. |
| 500,001 rows | With allocation forced to fail, an 8,000,032-byte request reaches that call. |
| Large counts in `capacity.tsv` | The size guard reaches the capacity failure call without an allocation. |

The large count controls do not allocate the requested size or enter the sorter. They establish the input and failure boundary only; allocator, panic and unwind behavior are not executed. The driver also compares its count with 4,097; the 4,096 and 4,097 row fixtures take opposite edges and both sort correctly. The table does not imply an actual validator set of either size.

A standalone call to the small partition with at least two rows checks that its scratch capacity is at least `n + 16` rows; the smaller capacity controls reach the `ud2` at `0x338be72`. Zero- and one-row controls bypass that check. `contracts.tsv` records the exact inputs and observed stops. These deliberately malformed direct calls do not establish that the real host can pass an undersized buffer.

The pivot's three-way controls return a row whose key is the median of the three keys, including equal keys. Its recursive controls separately check three groups of three sampled rows before the final selection. For example, all three equal keys select the second input row in the tested three-row form; see `pivot.tsv` for all results. These tests do not establish all recursion depths.

For the ascending 129-row fixture, `paths.tsv` shows that the entry and driver run, while the partition, small partition and pivot are not visited. A cyclic 65-row fixture visits all five selected functions. This is a statement about those fixtures, not a reachability claim for chain state.

### Inferences

The earlier snapshot packet ties the rows to validator keys and target stake. On that basis this sort supplies the key order needed by its existing builder. The actual snapshot filter's row order and the ability of real state to produce each synthetic distribution are not independently established by this packet. Function names such as driver and partition are analytical labels, not recovered symbols. The test's modeled allocation failure does not establish whether a live node can encounter it or how unwinding releases other resources.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. There is no source-built node, compiler/linker comparison, normalization mask, helper closure or whole-ELF identity claim. The decoder and bounded interpreter are adapted from the repository's MIT-licensed staking analysis; the independent Python sort and pivot rules are test oracles, not recovered Rust. Allocator, free, copy, comparison and failure calls use checked hooks, not native implementations. No captured node or visor process is started.

## Results and limitations

- Five selected FDE windows contain 5,356 bytes and 1,355 linearly decoded instructions. The normal and direct control fixtures visit 1,249 instruction starts; 63 of 93 conditional sites take both edges in the normal sort fixtures. These counts are local to this packet, not component coverage.
- 477 sort fixtures, 35 pivot fixtures, 8 direct small-partition controls and 10 injected allocation or size controls matched their stated independent expectations. The 33 focused unit tests pass with zero skips, including changed digest, altered code and relocation bytes, out-of-range and NOBITS mappings, unsorted and duplicate rows, buffer guards and failure boundaries.
- Each of 93 conditional instructions was inverted and tried against at most two already passing fixtures that reached it: 40 changed a compared result or free sequence, 18 stopped at an interpreter or modeled failure boundary, 32 survived those limited trials and 3 had no normal-sort witness. A modeled stop is not a prediction of a real corrupted process; survivors are unclassified and are not proof that branches are unnecessary. `mutations.tsv` records the individual outcomes. A separate small-partition inversion produces a different row result.
- The comparison hook models signed comparison results, not a particular libc implementation. Nonlocal calls, asynchronous failures, real allocation and cleanup, malformed native trees, all possible key distributions, and a compiled Rust comparison remain open. The already studied host and builder are linked by selected instruction bytes only. No progress gate is requested.

Next question: validate the snapshot consumer's treatment of the ordered rows and their target values under independently authored Rust, including real allocator failure and ownership cleanup in a separately authorized target-grounded harness.
