# RE-006: user-map deletion and tree repair on node 94

After a user-wide cancellation removes an entry from the book's user map, the node repairs the 20-byte-keyed, 80-byte-valued tree by replacing internal keys with predecessors, preferring the left sibling, and merging or redistributing at the observed 12-entry boundary; a reconstruction can preserve the user-map transition and its failure ordering.

- Component ID: `orderbook`, task `RE-006`.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a search lead only; no code was copied from it.
- Claim status: bytes, unwind ranges, selected branch and call targets, operands, and relocations are observations. Identifying the map as the book's user map uses prior book evidence; the structural projections are inferences. Runtime reachability, actual rollback, and original source function boundaries are unresolved.
- Scope included and excluded: six selected cursor, leaf, merge, redistribution, and ancestor-repair FDEs, plus bounded instructions at the already documented map-removal call and root-shrink continuation. The enclosing cancellation wrapper and map search are prior context, not newly selected functions. Allocator and panic internals, concurrent access, full transaction effects, and other releases are excluded.

## Reproduce

Run from the repository root with Python 3.12.3 on Linux x86-64 and the authenticated artifact. GNU objdump 2.42 was used for human instruction-boundary inspection only. The generator imports `tools/elf_index.py` and `tools/fde_extents.py`, checks the complete input digest before output, reads file-backed ELF bytes, and does not invoke external programs or execute the captured binary.

```sh
python3 tools/artifacts.py verify
python3 tools/book_user_map_erase94.py --out research/work-items/RE-006-user-map-erase-repair-94
python3 -m unittest tests.test_book_user_map_erase94
python3 tools/catalogue.py --check
(cd research/work-items/RE-006-user-map-erase-repair-94 && sha256sum -c MANIFEST.sha256)
```

For an independent regeneration comparison, replace `<tmp-dir>` with a writable relative directory:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/book_user_map_erase94.py --out <tmp-dir>/a
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/book_user_map_erase94.py --out <tmp-dir>/b
diff -r <tmp-dir>/a <tmp-dir>/b
diff -r -x README.md -x MANIFEST.sha256 <tmp-dir>/a research/work-items/RE-006-user-map-erase-repair-94
```

The generator writes `functions.tsv`, `witnesses.tsv`, `constants.tsv`, `branches.tsv`, `calls.tsv`, `indirect.tsv`, `relocations.tsv`, `diagnostics.tsv`, `repair-cases.tsv`, `header-count-cases.tsv`, `structural-cases.tsv`, `two-level-case.json`, and `summary.json`. The manifest also covers this README. Every reported target coordinate, byte, operand, relocation, and diagnostic record is extracted from the authenticated ELF; the case and projection files are explicitly synthetic.

## Evidence

Addresses below are linked ELF virtual addresses before load bias; ends are exclusive. File offsets, complete original bodies and hashes, FDE/CIE/LSDA coordinates and sizes are in `functions.tsv`. Each selected start is bound to both an FDE and its `.eh_frame_hdr` entry. An FDE extent is an unwind-described range, not proof of a source-level function boundary.

| Selected role | FDE range | Bytes |
| --- | --- | ---: |
| Leaf or predecessor cursor | `0x42b6040..0x42b63ea` | 938 |
| Leaf delete and first repair | `0x42a1bf0..0x42a1ee0` | 752 |
| Merge | `0x4283610..0x4283ac8` | 1,208 |
| Borrow from left | `0x4276080..0x42764fb` | 1,147 |
| Borrow from right | `0x4279bc0..0x427a0b2` | 1,266 |
| Upward repair | `0x41d6110..0x41d66dc` | 1,484 |

The earlier `RE-006-user-book-cancel-94` evidence identifies a user-wide cancellation that removes the user's entry after processing its orders. At the bounded call site `0x4945c58`, its map-removal implementation calls the selected cursor. The same continuation decrements the header count at `0x4945cb4` and conditionally contracts the root. That qword decrement has no local zero guard: a hypothetical zero count wraps to `u64::MAX`, but the evidence does not establish that such an inconsistent tree is reachable. This packet does not select or remap that preexisting caller. The earlier `RE-006-prune-book-user-states-94` packet identifies the relevant book user map and its value fields; the 20-byte user and 80-byte entry labels here rely on that evidence. These links do not establish exclusive book ownership of the generic tree helpers.

### Node and cursor

| Observed node field | Use |
| --- | --- |
| `+0x00`, stride `0x50` | Value slots; the cursor moves five 16-byte chunks per value. |
| `+0x370` | Parent pointer. |
| `+0x378`, stride `0x14` | Key bytes: 16-byte load/store plus a four-byte load/store. |
| `+0x454`, `+0x456` | u16 parent edge index and u16 live-key count. |
| `+0x458` | Child-pointer array, stride eight. |
| `0x458`, `0x4b8` | Release-size arguments on leaf and internal-node paths, respectively. |

These offsets and sizes are recorded machine operands, not a recovered Rust ABI. The cursor takes the direct-leaf arm when its input height is zero. Otherwise it enters the child before the selected key and follows rightmost children using each node's live count, then calls the leaf deletion with the last key. After repair, it exchanges the 20-byte key and the associated 80-byte value with the selected internal position. The unrolled descent uses groups of eight; the available evidence does not prove malformed pointer safety.

### Delete and repair

The leaf routine saves the removed key and value, shifts their following suffixes separately, and writes the decremented u16 count. If the new count is above four it skips the initial underflow repair. If the leaf has no parent it also skips sibling selection. Otherwise a nonzero parent-edge index chooses the left sibling, while edge zero chooses the right sibling and requires a nonempty parent.

For a well-formed non-root leaf that initially has five keys, removal leaves four keys. The comparison uses the *old* leaf count plus the sibling count; this is the remaining count plus the sibling count plus the parent separator.

| Sibling count | Total including separator | Selected action |
| ---: | ---: | --- |
| 5 or 6 | 10 or 11 | Merge. |
| 7 through 11 | 12 through 16 | Borrow one entry from the selected sibling through the parent. |

The merge helper rejects a resulting count at least 12 and checks the tracked cursor index before its node-count store. The redistribution helpers reject a destination count at least 12 and an unsigned donor subtraction that borrows before their count stores. The left helper has an additional length-consistency branch after some count stores and copies. The helpers move keys and values and, for internal nodes, update moved children's parent pointers and edge indexes.

Following a merge, upward repair stops when the current count exceeds four. Otherwise it again prefers a left sibling and compares `current + sibling + 1` against 12. A merge removes a parent separator and may continue upward; a redistribution requests `5 - current` items and returns. If upward repair reaches an empty root it returns zero and the leaf routine sets a flag. On the selected continuation, a set flag requires a nonnull root and nonzero height, installs the first child, reduces height, clears the child's parent, and passes the former root with size `0x4b8` to the relocated release slot. A root leaf without a parent does not take that contraction branch in the selected leaf routine.

Human-readable instruction excerpt; the collector reads the bytes rather than this text:

```text
42a1ceb  cmp    ax, 0x4
42a1cef  ja     0x42a1d5b
42a1d46  cmp    edi, 0xc
42a1d49  jae    0x42a1de9
```

### Failure observations

| Selected guard | Destination | Observed ordering |
| --- | --- | --- |
| A first-child repair has an empty parent | `0x42a1ea7` | The leaf's key/value shifts and count store precede it. |
| Merge cursor index exceeds the selected side | `0x4283a7d` | Before the merge's node-count store. |
| Merged count is at least 12 | `0x4283a96` | Before the merge's node-count store. |
| Redistribution destination is too large or donor count underflows | `0x42764b0`, `0x42764c9`, `0x427a080`, `0x427a099` | Before the respective redistribution count stores. |
| Left redistribution copy lengths disagree | `0x42764e2` | After its count stores and initial copies. |
| Upward repair needs a separator in an empty parent | `0x41d66c3` | A prior leaf deletion or merge may already have occurred. |
| Root-shrink flag is set with null root or zero height | `0x4945dd9`, `0x4945de8` | The caller's header-count decrement has already occurred. |

A cleanup-shaped tail saves a machine return value, passes the saved leaf payload to an external routine at `0x41d5b70`, and then calls the external edge at `0x5660110`. The entry conditions, cleanup routine body and exception-action table are not decoded. These are selected static paths; the table does not assert that malformed states are reachable or that failure leaves any particular final state. `diagnostics.tsv` retains literal bytes, location records, line and column numbers, a hash of the embedded full source path, and only the relative suffix `src/collections/btree/node.rs`. Some literal spans contain adjoining text, so they are not presented as complete rendered errors. A diagnostic source location is not evidence of an original function boundary.

`relocations.tsv` identifies the imported `memcpy` and `memmove` slots from the ELF dynamic symbol table. The release and failure slots are recorded with relocation addends, without claiming their full implementations. `branches.tsv` and `calls.tsv` are selected sites rather than a complete CFG. The only context outside the six FDEs consists of the bounded caller windows noted above.

### Projections and controls

`repair-cases.tsv` enumerates 120 combinations of underfull count, sibling count and side from the extracted thresholds. Some are deliberately noncanonical; none claims target reachability. `structural-cases.tsv` contains 24 independently authored, ordered key/value examples for both sides, four sibling sizes and three removed positions. `header-count-cases.tsv` projects four values around the qword decrement, including the inconsistent zero-count case. The focused tests compare the projected resulting ordered key/value sequence to the independently constructed original sequence minus the removed pair, and reject corrupted order and invalid ranges. `two-level-case.json` projects one first-child leaf merge, a second merge at its parent, and contraction of the empty root. Its ordered 71 synthetic key/value pairs reduce to 70 after deleting the selected pair; the test independently checks the resulting order, the ten-key root and its eleven children. These are models of the pinned branch reading, not executions or emulations of node #94.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Compiler and linker settings, two-build comparison, raw and normalized Rust-to-target comparison, masks, allocator and panic behavior, vtable and relocation closure, runtime fixtures, and whole-ELF equivalence: not yet measured. No target code is transplanted or executed.

The focused unittest suite checks the input digest, selected body hashes and witnesses, FDE extents and header bindings, selected conditional instruction bytes and targets, direct call graph, relocation slots and source locations, mapping bounds and NOBITS exclusion, and synthetic boundary and corruption controls. The controls do not validate target runtime behavior.

## Results and limitations

The selected denominator is six FDE ranges totaling 6,795 bytes, 29 fixed witnesses, 12 decoded constants, 25 selected conditional branches, 11 direct calls, nine indirect sites, four relocation slots, and ten diagnostic sites. The generator produces 120 decision rows, four counter projections, 24 structural projection rows and one two-level example; these are synthetic and are not a function-coverage measure. The focused suite passed 23 unittest methods with zero skips. Two regenerations with different hash seeds and time zones were byte-identical; artifact verification and catalogue consistency passed. No component completion gate is requested.

The selected branch list is not exhaustive. The prior caller's search and the enclosing cancellation's order effects are not re-proved here. The synthetic model omits allocator effects, concurrency, all unwind landing pads and arbitrary malformed trees; no rollback or target-executed equivalence is claimed. Next question: establish how a successful outer user-entry removal interacts with its vector and two nested map drops, including cleanup and unwind behavior, without reusing the already mapped deletion functions as new subjects.
