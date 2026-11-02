# staking: inner delegation-row deletion and merge in node #94

This packet establishes how an inner delegation or epoch-member row is compacted and how its gap survives a sibling merge, including child-link updates and the signal that the enclosing map must shrink an empty root.

- Component ID: staking, stake accounting and validator lifecycle.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred reference is a lead, not implementation source.
- Claim status: observation for byte witnesses, relocation records and FDE ranges; inference for map ownership based on the prior state and caller evidence; unexercised branches and external effects are unresolved.
- Scope included and excluded: two previously unselected FDE ranges, their direct edge, selected incoming instructions, compaction and the merge subtree. The cursor adapter, existing enclosing economic actions, the two directional borrow bodies, allocation implementation, unwinding, malformed arbitrary trees, and node #115 are outside the selected ranges. Incoming instructions are linkage context only. No staking progress gate is requested.

## Reproduce

From the repository root, with Python 3.12.3 and the standard library:

```sh
python3 tools/staking_inner_removal94.py --out research/work-items/staking-inner-removal-94
python3 -m unittest tests.test_staking_inner_removal94
```

The tool verifies the input SHA-256 before parsing and uses the repository's `tools/elf_index.py` and `tools/fde_extents.py` for ELF sections and FDE/CIE records. It runs no external program. Its x86 decoder and interpreter are adapted from the MIT-licensed `tools/staking_stake_accounting.py`; its fixtures and checks for these ranges are specific to this packet. It models instructions on synthetic memory, not a running node process. Regeneration was repeated with different hash seeds and time zones and with a `PATH` containing no binutils; a recursive byte comparison of the generated output directories was equal. The optional human-readable disassembly below was inspected with GNU objdump 2.42; it is not input to the tool or tests.

`functions.tsv`, `instructions.tsv`, `branches.tsv`, `calls.tsv`, `incoming.tsv`, `anchors.tsv`, `relocations.tsv`, `leaf-cases.tsv`, `merge-cases.tsv`, `corruption.tsv`, `mutations.tsv` and `summary.json` are generated. `MANIFEST.sha256` covers these files and this README.

## Evidence

All addresses in this section are linked ELF virtual addresses. `functions.tsv` records file offsets, actual FDE and CIE addresses, half-open ranges and body hashes. The FDE is an unwind description, not proof that every function in the ELF is indexed or that its source boundary is known. Both selected ranges lie entirely in a file-backed executable section; neither FDE has an LSDA.

| Selected role | FDE range | File offset | FDE VA | Bytes |
| --- | --- | --- | --- | ---: |
| Inner leaf deletion and repair | `0x2fc8d70..0x2fc95a9` | `0x2fc7d70` | `0xdd4c38` | 2,105 |
| Merge and translate gap | `0x2fae350..0x2fae795` | `0x2fad350` | `0xdd4418` | 1,093 |

### Connection and node shape

The call at `0x33abc4b` and the call at `0x33abe68` both reach the cursor adapter at `0x2fd6ec0`; two call instructions in that adapter reach the selected leaf routine (`incoming.tsv`). The already studied `staking-stake-accounting-94` identifies those enclosing callers with member-row and delegation-row removal. This packet checks the incoming instruction bytes but does not reanalyse or claim those prior functions. The shared adapter also occurs in other contexts, so the two links alone do not imply that all its callers are staking operations.

The selected bytes address keys at node `+0x110` in 20-byte strides and values at `+0x08` in 24-byte strides. Parent pointer, parent edge index, node count and child array are at `+0x00`, `+0x1ec`, `+0x1ee` and `+0x1f0`, respectively. The selected deletion returns the removed key and value plus a node, height and gap index. The meanings of those bytes as the two inner staking maps follow from the preceding caller and serializer evidence; they are not names encoded in these functions.

### Deletion and repair decisions

The following table is a reading of the selected branches. `n` is the leaf count before deletion and `s` is the chosen sibling count. `n + s` is also the resulting merged count because the deletion removes one row and the parent contributes one separator.

| Condition | Observed action |
| --- | --- |
| Removed row has a suffix | Move subsequent keys and values left; decrement the 16-bit count. The single-leaf controls compare the entire node to an independent byte projection, including the stale final slots. |
| New count at least 5 | Return the gap without sibling repair. |
| New count at most 4 and parent is absent | Return the gap; the root leaf is allowed to be smaller. |
| Parent edge is nonzero | Select the left sibling. |
| Parent edge is zero | Select the right sibling; a parent with no separator goes to a panic boundary. |
| `n + s < 12` | Call the selected merge routine; its returned gap is used for subsequent repair. |
| `n + s >= 12` | Call the corresponding directional borrow routine. The evaluator stops at that call; no post-borrow behavior is asserted here. |
| A merge makes the parent underfull | Continue upward, merging or handing off to a borrow routine. |
| The repair reaches an empty internal root | Write byte 1 through the supplied flag pointer. The caller's anchored instructions test that byte and load the first child as the replacement root. |

A short disassembly excerpt, shown only for human inspection:

```text
2fc8e4b: 66 83 f8 04          cmp ax, 4
2fc8e4f: 0f 87 90 00 00 00    ja  0x2fc8ee5
2fc8ec5: 83 fb 0c             cmp ebx, 12
2fc8ec8: 0f 83 aa 00 00 00    jae 0x2fc8f78
2fc8f71: e8 da 53 fe ff       call 0x2fae350
```

### Merge contract and failures

The merge routine receives a parent/separator and two adjacent children. On the exercised valid cases it appends the separator and right child's rows to the left child, shifts the parent's remaining keys, values and child pointers, decrements the parent's count, and frees the right child. For an internal child it moves all child pointers and repairs their parent pointers and edge indices. The returned gap points into the left child: a gap originally in the left keeps its index; a gap originally in the right gets `left_count_before + 1` added. The bit controlling this choice is read from the low bit of the input, not a separately validated enum.

`merge-cases.tsv` covers leaf and internal children, both gap sides, all gap positions of the selected four occupancy pairs, and separator positions in parents with 1, 3, 6 or 11 rows. These are synthetic helper inputs; the table does not assert that every combination is reachable through a live staking transaction. `leaf-cases.tsv` separately includes valid single leaves, two-child trees and multilevel repairs. For the two copy slots and the free slot, `relocations.tsv` retains the original relocation records; fixture hooks provide copying, freeing and panic termination rather than executing those external implementations.

Two invalid gap descriptors and one overfull merge descriptor reach the selected routine's particular panic branches before any fixture node bytes change or any node is freed. A fourth control gives an empty internal parent: the deletion compacts the leaf first, then reaches the empty-parent panic without changing the parent or freeing a node (`corruption.tsv`). The additional arithmetic consistency failure and other panic or unwind paths are not dynamically covered. Its branch is retained in `branches.tsv`; no broad malformed-state behavior is claimed.

### Controls and interpretation

The 1,052 leaf fixtures include 982 completed projections and 70 cases stopped at the borrow boundary. All completed cases compare removed key and value, the whole live sorted tree, continuation successor, root flag and free count. Boundary cases verify the selected borrow side, ordered rows and parent links before the hook; the first-level cases also compare the compacted leaf bytes. The 920 direct merge fixtures compare rows, gap translation, parent count, the freed node and moved child links. They include height-zero and height-one children and non-edge parent separators.

Eleven targeted single-byte changes are detected (`mutations.tsv`), covering the minimum occupancy, merge cutoffs, equality at the gap limit, capacity, removed count, returned gap, parent count, free size and the empty-root flag. Every mutation first runs its corresponding unmodified fixture. These controls support the selected tests; they are not an exhaustive search for equivalent or surviving changes.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo build scope and lockfile, compiler and linker flags, repeated builds, raw/normalized compiled-code comparisons and normalization masks are **not yet measured**. There is no binary transplantation. Copy, free, panic and the two previously studied borrow routines are modeled boundaries, and no allocator, runtime unwind, indirect-call closure or whole-ELF comparison is claimed.

## Results and limitations

- Selected denominator: 2 FDE ranges, 3,198 bytes and 643 linearly decoded instruction rows; 598 rows were reached by at least one selected fixture. This denominator is only these ranges, not a component census. `branches.tsv` retains both targets and per-edge counts, including one-sided and unreached branches.
- Completed checks: 982 full deletion fixtures, 70 checked borrow-boundary fixtures, 920 direct merge fixtures, 4 corruption controls and 11 targeted mutations; 14 unit tests passed with no skips.
- The emulator checks a subset of x86 against synthetic memory and modeled boundaries. It does not prove real allocator behavior, runtime exceptions, all valid B-tree heights, or side effects of the enclosing undelegation action. The incomplete borrow paths are not counted as complete deletion cases.
- The two 24-byte value types share this low-level instantiation in the selected callers; their higher-level economic meaning and the actual path through the enclosing action rely on earlier packets. No independent Rust or node #115 comparison was made.

Next question: can an independent Rust inner-map removal preserve this gap and ownership contract when joined to the separately studied borrow helpers and the caller's root replacement?
