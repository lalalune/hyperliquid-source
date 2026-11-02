# RE-006: long cancellation-ID sort on node 94

This packet replaces the previously stubbed long-sort edge in a user-wide cancellation with a binary-backed path through run detection, partition dispatch, small sorting and pivot selection, enabling reconstruction of its scratch and failure boundaries.

- Component ID: `orderbook`, task RE-006 (user-wide cancellation).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a lead.
- Claim status: bytes, selected instruction operands, FDE records, branch destinations and relocation bindings are observations. Function-role names, ordering interpretation and synthetic calculations are inferences or projections, as specified below. No target code was executed.
- Scope included and excluded: five previously unrecorded sort-related FDEs, selected context call sites from user cancellation into sorting and onward to tree iteration/removal, and selected failure/exception edges. The existing caller, collectors, long-sort allocation wrapper, tree builder, removal routines, complete sorter behavior and allocator contracts are excluded as subject bodies.

## Reproduce

Run from the repository root with the authenticated node artifact and Python 3.12.3. The tool reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, including the shared ULEB decoder, and validates the full SHA-256 before analysis. It never launches the node, visor, a disassembler or any other program. GNU objdump 2.42 with Intel syntax was used only for manual reading; its output is not an input or generated evidence.

```sh
python3 tools/artifacts.py verify
python3 tools/book_cancel_sort94.py --out research/work-items/RE-006-cancel-id-long-sort-94
python3 -m unittest tests.test_book_cancel_sort94
python3 tools/catalogue.py --check
```

For an independent byte comparison, replace `<tmp-dir>` with a writable relative directory:

```sh
python3 tools/book_cancel_sort94.py --out <tmp-dir>
diff -r <tmp-dir> research/work-items/RE-006-cancel-id-long-sort-94 -x README.md -x MANIFEST.sha256
```

Generated evidence is deterministic across hash seeds and time zones. `MANIFEST.sha256` covers this README and all generated evidence. All addresses below are linked ELF virtual addresses; `functions.tsv` separately records file offsets, complete raw FDE bytes, their hashes, and FDE/LSDA coordinates. An FDE describes an unwind range and is not alone proof of a source-function boundary.

## Evidence

### Cancellation context and selected functions

Existing `RE-006-scheduled-cancel-fire-94` and `RE-006-user-book-cancel-94` establish the per-user cancellation context: collected keys are sorted as unsigned qwords, inserted into a set, and removed in set order. Their evaluator replaced the large-sort target at slot `0x5774f50` with a sorting stub; it did not establish the actual long-sort internals.

The recorded spot-context edges include the user-sweep call at `0x26e4441` to a collector adapter, its call to a collector at `0x27e7cba`, the long-sort call at `0x27e7ea6`, the tree-builder call at `0x27e7d4e`, the tree-iterator call at `0x26e4536`, and the removal call at `0x26e457f`. A second context call at `0x27e6bd1` reaches the same long-sort slot. These are bounded call-site observations; the older enclosing bodies are not newly selected subjects. The continuation after sorting and the cancellation ordering use the earlier packet's established context, not a newly executed fixture here.

| Selected role | FDE range, half-open | Bytes | FDE record |
| --- | --- | ---: | --- |
| Partition dispatch and recursion | `0x4497a90..0x4498022` | 1426 | `0xed52f0` |
| Recursive pivot selector | `0x45c35b0..0x45c366f` | 191 | `0xee8320` |
| Four-item selection network | `0x4912a50..0x4912d13` | 707 | `0xf17fcc` |
| Small sorter | `0x4918d30..0x49190b7` | 903 | `0x12a6ee4` |
| Run and merge coordinator | `0x4dbd490..0x4dbdb5e` | 1742 | `0xf4b840` |

`calls.tsv` decodes 21 selected edges. The two call sites to `0x5774f50` have an `R_X86_64_RELATIVE` addend naming the previously recorded wrapper `0x4486d10`; that wrapper calls the selected run coordinator. Four coordinator calls use slot `0x57768a0`, whose relative relocation names the selected partition function. Partition calls the small sorter and pivot, recursively calls itself through the same slot, and can call the run coordinator as a fallback. The small sorter calls the four-item network twice; the pivot calls itself recursively. `relocations.tsv` retains the two raw ELF relocation records. None of these edges alone proves runtime reachability for every input.

### Book-state and slot context

The following offsets come from the selected caller and collector instruction windows, not from an inferred reference layout. `layout.tsv` records each raw immediate and its address.

| Object | Offset or value | Observed use |
| --- | --- | --- |
| Book | `+0xb8` / `+0xc0` | user-map root and accompanying height-shaped qword read in the sweep context |
| Collector input | `+0x48` | pointer used as the slab header |
| Slab header | `+0x08` / `+0x10` | entry pointer / entry-count bound |
| Slot | stride `0xf8`, low dword `2` | index is scaled; an out-of-range index or tag `2` returns to the collector loop |
| Live slot | `+0xd8` | qword key address supplied to the collection path |
| Returned tree node | `+0x08 + 8 * index` | qword loaded as an argument to the already studied removal call |

These context windows bind the sorting subpath to the book and live-slot layout; they do not establish that every input state reaches a removal.

### Size and scratch decisions

`anchors.tsv` pins exact byte windows; `branches.tsv` decodes 21 selected conditional destinations. The values in this table are extracted from those instruction encodings.

| Point | Observed boundary or calculation |
| --- | --- |
| Spot cancellation context | `0` or `1` qwords skip sorting; `2..20` take the inline path; `21` or more call the long-sort slot. |
| Context scratch wrapper | `scratch = max(min(n, 1000000), n - floor(n / 2))` qwords. Scratch of at most `512` uses the stack buffer; `513` or more uses allocation. The flag passed to the run coordinator is 1 for `n < 65`, otherwise 0. |
| Run coordinator | `n < 2` returns. For `n < 4097`, the stored run threshold is `min(64, n - floor(n / 2))`; at `4097` and above it changes to the calculation below. |
| Partition | Lengths below `33` call the small sorter. A length at least `64` takes the recursive pivot-helper call; shorter partitions select among three locally loaded keys. A depth decrement with borrow takes the coordinator fallback. |
| Small sorter | Length below `2` returns. For the partition call with `n <= 32`, the checked scratch count must be at least `n + 16`; smaller counts reach `ud2`. It uses different small-sort paths at `7/8` and `15/16` and calls the four-item network on the larger path. |

For `n >= 4097`, the run coordinator sets `k = ceil(floor(log2(n | 1)) / 2)` and stores `((n >> k) + (1 << k)) >> 1`. It also computes `ceil(2^62 / n)` after the `n >= 2` gate. `buffer-projections.tsv` and `run-projections.tsv` show synthetic arithmetic examples, including 20/21, 512/513, and 4096/4097. The 20-row projection describes the wrapper's arithmetic, not a claim that the cancellation context calls that wrapper for 20 entries. Large capacities are arithmetic projections, not proved allocatable input states.

### Comparison behavior and failures

The selected run scan compares qwords unsigned. On the ascending arm, a strictly smaller next key stops the run; on the descending arm, a next key greater than or equal to the previous key stops it before reversal. Consequently equality follows the ascending arm and terminates the descending arm. The two selected merge loops use unsigned comparisons: the forward loop chooses its first loaded operand when it is strictly smaller and otherwise its second; the backward loop chooses its first loaded operand when strictly greater and otherwise its second. `merge-projections.tsv` records only these local scalar choices. Plain qword keys carry no independent payload identity here, so this does not establish global stable ordering.

For the checked first four-key network in the small sorter, the independent projection agrees with ordinary unsigned sorting for 256 combinations of four small values. A deliberately changed middle selection differs on 92 combinations. For the pivot leaf's three-way selection, a separate model selects a median value in all 64 combinations; a changed choice differs on 14. These are models of pinned byte sequences, **not** execution, lifting or emulation of the target; they do not prove all partitions or merges correct.

The wrapper checks local scratch layout and a null allocation result before entering the coordinator. Partition contains a scratch-size failure edge ending at `0x4497ff1` (`ud2`); the small sorter has its own scratch guard at `0x4918d4f` ending at `0x4919097` (`ud2`). A separate call at `0x4919091` falls in an LSDA range whose landing is `0x4919099`; that landing copies `n * 8` bytes before the unwind-resume target. `unwind.tsv` retains all three entries of this selected LSDA using the shared ULEB reader. This describes the static call-site mapping, not whether the callee actually unwinds or whether every failure has equivalent effects.

### Inferences and unresolved points

- The qwords are order IDs and the surrounding tree is used for deduplication and ascending cancellation, from the existing cancellation packets and the newly pinned edges. The selected functions themselves only operate on qword values and pointers; original Rust names are not established.
- The run, partition and pivot labels are inferred from local comparison and data movement. Full correctness of the coordinator, partition loop, recursive sort, merge completion, allocator failure effects and all exception paths remain unresolved.
- The context wrapper, collector and final removal bodies were already studied and are not included as selected FDEs. Previously documented sorting of 40-byte trigger candidates is a different input layout and a different path.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Compiler/linker options, lockfile, source-to-target body comparison, helper/data/relocation closure, runtime unwind behavior and target-executed boundary fixtures are **not yet measured**. The complete five FDE byte strings are retained with raw SHA-256 hashes; no operand normalization or target-code transplantation is used. The small models check a proposed interpretation against ordinary Python order/median operations, not against executed node behavior.

The focused suite checks exact digest, FDE/index bindings, complete body hashes, 28 byte anchors, nine decoded layout immediates, selected call and branch targets, both relocation records, the exception table, NOBITS and out-of-range rejection, scratch and arithmetic boundaries, and independent network/pivot examples. Corruption controls alter a digest, one byte per anchor, an unpinned body byte, call displacements, a relative relocation, a branch opcode, and an LSDA header and landing.

## Results and limitations

The retained evidence contains 5 FDE ranges totalling 4969 bytes, 21 checked calls, 21 selected branches, 2 relative relocation records and 3 selected exception call-site records. The 256 four-key and 64 pivot rows are synthetic projections; they are not target runs or whole-function coverage. Twenty-two focused unittest methods passed with no skips, including in a binutils-free execution path.

No component progress gate is requested. The packet does not establish complete cancellation, global sort correctness, a Rust implementation, observable target behavior or binary equivalence. Next question: independently validate the remaining partition and merge paths and the long-sort wrapper's allocation/error contract against approved target-grounded fixtures.
