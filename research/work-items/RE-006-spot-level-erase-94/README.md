# RE-006: spot price-level erasure and B-tree repair

This packet makes it possible to reconstruct how an empty spot-book price level is erased, including predecessor substitution, both sibling repair directions, tracked-edge adjustment, and root contraction.

- Component ID: `orderbook` (RE-006, book transitions).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` was a lead only, not copied or treated as authoritative.
- Claim status: byte and FDE observations below; semantic roles and source attribution are inferences; native behavior, complete book behavior, and identity remain unresolved.
- Scope included and excluded: one spot empty-level deletion through six selected FDEs, with caller-side byte windows only; other cancel work, insertion, slab mutation, allocator internals, live execution, and all other releases are outside scope. The earlier price-level lifecycle packet covers its separate removal caller; this packet selects none of its function addresses.

## Reproduce

Run from the repository root using Python 3 and the standard library. The recorded environment is Python 3.12.3, Linux x86-64; GNU objdump 2.42 was used only for a manual instruction-boundary review. The generator and tests never invoke it or any other external program. The evaluator is adapted from the repository's MIT-licensed `tools/queued_row_rewrite.py`, with task-specific fixtures and controls. It reads the authenticated file as data and never runs the captured executable.

```sh
python3 tools/artifacts.py verify
python3 tools/spot_level_erase94.py --out research/work-items/RE-006-spot-level-erase-94
python3 -m unittest tests.test_spot_level_erase94
python3 tools/catalogue.py --check
```

To check reproducibility, replace the two placeholders with distinct relative output directories and compare them:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/spot_level_erase94.py --out <dir-a>
PYTHONHASHSEED=37 TZ=Pacific/Honolulu python3 tools/spot_level_erase94.py --out <dir-b>
diff -r <dir-a> <dir-b>
```

`MANIFEST.sha256` records the retained packet files. The tool verifies the target digest before parsing; it uses the shared `elf_index` and `fde_extents` parsers, excludes NOBITS sections from file-backed reads, rejects duplicate FDE starts, checks fixed body hashes, and checks every chosen body decodes to its FDE end. Its generated output does not depend on binutils rendering, time, locale, or absolute paths.

## Evidence

Addresses are linked ELF virtual addresses. The relevant `.text` file offsets are the virtual addresses minus `0x1000`; `functions.tsv` also gives each offset, raw body hash, and FDE address. An FDE is an unwind-described extent, not by itself proof of an original source-function boundary. Direct calls into the selected starts support the entrypoint interpretation. `windows.json` contains complete byte strings for the six FDEs and both caller gates; `anchors.tsv` extracts shorter windows. `branches.tsv` lists all conditional branches decoded across these extents, with bytes and both destinations; `calls.tsv` includes direct and indirect calls. The decoder is bounded to these six FDEs.

| Inferred role | FDE range, half-open | FDE bytes |
| --- | --- | ---: |
| erase entry and root handling | `0x28666e0..0x286686c` | 396 |
| leaf or predecessor selection | `0x1b21b80..0x1b21e31` | 689 |
| leaf deletion and upward repair | `0x1b1f0b0..0x1b1f8d9` | 2,089 |
| merge siblings | `0x1b00aa0..0x1b00ec8` | 1,064 |
| borrow from left sibling | `0x1af8b70..0x1af8ebb` | 843 |
| borrow from right sibling | `0x1afb1f0..0x1afb56f` | 895 |

At caller sites `0x26df231` and `0x26e02e7`, the preceding instructions test two byte tags at effective displacements `-0x20` and `-0x10`; either nonzero tag skips the call to `0x28666e0`. The caller-side search and link repair identify these as the empty-level gates: that meaning is an inference from the bounded caller windows and the previously documented level layout, not a claim to remap either caller body. `caller-gates.tsv` retains the exact bytes and both branch destinations. `caller-gate-cases.tsv` evaluates 32 tag combinations at those bounded windows: only the two both-zero cases reach their call sites.

The entry reads a root pointer, height, and total count at map offsets `+0`, `+8`, and `+0x10`. Its signed key search reads a node's 16-bit key count at `+0x1c2`, compares qwords beginning at `+0x168`, and follows child pointers at `+0x1c8`. The 32-byte values begin at node `+0`, with stride `0x20`. A child stores its parent pointer at `+0x160` and 16-bit parent edge index at `+0x1c0`. On a missing key the entry returns a leading qword `2` without changing the map. On a hit it returns the removed 32-byte value and decrements the map count. The source-level type and meaning of every value byte remain unresolved.

The hit path is `0x286679f -> 0x1b21b80 -> 0x1b1f0b0`. A leaf hit removes the indexed entry. An internal hit walks to the rightmost edge of its left child, removes the predecessor from a leaf, and exchanges that key and its 32-byte value into the vacated internal position. The helper returns the removed key/value and a cursor; in the direct cursor fixtures, a leaf deletion returns its old slot index, while the tested internal hits return the first leaf edge in the right subtree. Those cursor observations are bounded by the listed fixtures, not a proof of all cursor cases.

For a valid non-root leaf starting with five entries, deleting one leaves four and selects a sibling. A nonzero parent edge index selects the left sibling; edge zero selects the right. The table below describes the observed decision in this valid one-deletion case:

| Post-delete entries | Sibling entries | Decision |
| ---: | ---: | --- |
| at least 5 | any | no local underflow repair |
| 4 | 5 or 6 | merge both siblings with their parent separator; resulting size is at most 11 |
| 4 | 7 through 11 | transfer one entry through the parent separator from the selected sibling |

The machine checks the merged length against `0x0c` and treats a value at least 12 as a failure; 11 is accepted. For a general underfull count, the borrow call supplies `5 - count`. Merge and redistribution move both qword keys and 32-byte values; internal-node cases also move edges and repair their parent pointers and indices. Merging removes one parent separator and releases the right node. If this makes a non-root parent underfull, repair continues upward. When the root becomes empty after an internal merge, the caller promotes its sole child, decrements height, clears the promoted child's parent, and releases the former root. A root that was already a leaf stays allocated when its last entry is removed in the tested cases.

`0x1b00aa0` also returns an edge cursor. In direct helper fixtures, selector bit zero tracks a left edge unchanged, while selector bit one adds `left_count + 1` to a right edge. Indices through the selected sibling's count are accepted in the tested cases. The separate helper tests cover counts on both sides of that bound and a merge result of 11 entries; they are synthetic helper contracts, not evidence that every such call is reachable from a book cancel.

`failures.tsv` retains ten deliberately malformed helper cases, with pointer-and-length text spans read from the ELF at the failure call. A span can contain adjoining literals and is not a claim about the final rendered panic text:

| Helper | Failing condition observed in the synthetic call | Failure call site |
| --- | --- | --- |
| merge | tracked edge exceeds either selected sibling's length | `0x1b00e90` |
| merge | left length + right length + separator is at least 12 | `0x1b00ea9` |
| borrow left | right length + transfer count is at least 12 | `0x1af8e83` |
| borrow left | left length is below transfer count | `0x1af8e9c` |
| borrow right | left length + transfer count is at least 12 | `0x1afb550` |
| borrow right | right length is below transfer count | `0x1afb569` |
| borrow left / right | one child height is zero and the other is not | `0x1af8da8` / `0x1afb47a` |
| leaf repair | underfull child has a zero-key internal parent | `0x1b1f8d3` |

These text spans are not evidence that the malformed cases are reachable in production. `relocations.json` independently identifies the dynamic `memcpy` and `memmove` slots; the evaluator stubs them with bounded copies, rejects overlapping `memcpy`, and stubs the observed node release with size checks and poison. Other panic calls stop the evaluator at the failure edge.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Build provenance, target ABI compatibility, raw/normalized compiled comparisons, masks, relocation closure beyond the retained slots, and whole-ELF identity: not yet implemented or measured. No binary bytes are transplanted into an implementation.

The collector interprets selected target instruction bytes in Python and compares the resulting map and cursor against a separately written structural model. The model checks signed key order, exact tree shape, attached values, counts, child-parent links, free sizes, and absence of reachable freed nodes. Calls outside the selected family are bounded copy, release, or panic stubs. `cases.tsv` has before/after shapes for 262 one-delete or missing-key fixtures; `sequences.tsv` records 424 operations on six evolving trees, including repeated missing deletes. `rotations.tsv`, `merges.tsv`, and `cursors.tsv` cover 20 direct multi-entry redistribution fixtures, 72 direct tracked-edge merge fixtures, and six direct cursor fixtures respectively. `descent-fragments.tsv` adds 17 sparse, deliberately incomplete chains to exercise eight-step loop boundaries; those chains are not valid full B-trees. The observed caller uses a one-entry borrow; larger direct transfers are helper-only tests.

`mutations.tsv` flips each of the 87 decoded conditional branches, selecting up to one witness per sampled fixture family and edge from the one-delete fixtures: 70 are detected, four survive those samples, and 13 are unreached by that mutation campaign. Three survivors concern internal cursor navigation whose returned cursor the wrapper does not consume; the fourth changes the tracked-edge guard, which the sampled wrapper fixtures do not distinguish. `focused-controls.tsv` separately detects all 14 selected byte corruptions, including direct-helper controls for those four branches and sparse-chain loop controls. Mutation outcomes include bounded evaluator failures and are sensitivity checks, not native differential execution.

## Results and limitations

The generator decoded 1,221 instructions in the six FDE extents; 1,170 were visited by at least one synthetic case, direct-helper test, failure case, sequence, or sparse fragment. Both edges were observed for 62 of 87 conditional branches in that combined set. These are evaluator coverage counts, not function coverage for the node. The 24 unit tests have no skips. The deterministic regeneration and repository checks are reported in the draft; no whole-component milestone gate is requested.

The Python interpreter and its structural oracle are independently reviewable but can share an interpretation error. The artificial heap cannot establish allocator behavior or production reachability, and the bounded stubs do not model unwinding. The remaining branches include malformed states and deeper paths. Next question: implement the established node and cursor operations independently in Rust, then compare an authorized offline insertion-and-deletion fixture without assuming this synthetic layout is a target ABI.
