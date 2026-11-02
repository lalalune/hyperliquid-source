# RE-006: spot cancellation change-index failure and cleanup

On the selected resting-slot branch of a spot cancellation, changed-user bookkeeping follows a successful user-slot deletion; its two index split helpers have different unwind records after root publication, so a reconstruction must retain those conditional cleanup distinctions instead of assuming that an index failure restores the earlier book state.

- Component ID: `orderbook`, task `RE-006`, spot cancellation bookkeeping.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: independent repository base `e5c9b6436876b2a4a39daef813171f9879317699`; unlicensed `references/can1357-hl` pin `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a search lead only; no reference code is copied.
- Claim status: bytes, selected instruction operands, FDEs, relocation records and LSDA call-site records are observations. Identifying the key as a slot and the maps as user and changed-asset indexes uses earlier book evidence and is an inference. Reachability of inconsistent trees, execution of an unwind, allocator effects and rollback remain unresolved.
- Scope included and excluded: six new FDEs covering the selected slot-set entry, two spot-specific split helpers, two cleanup wrappers and their drain step; bounded call sites in previously researched functions connect them. Earlier book removal, entry/search wrappers, allocator and error-handler bodies are context or external edges only. Complete cancellation, matching, all map operations, other releases and target execution are excluded.

## Reproduce

Run from the repository root with Python 3 and the authenticated node artifact. The recorded author environment is Linux x86-64, CPython 3.12.3 and GNU objdump 2.42. Objdump was used for manual instruction-boundary inspection only. The collector and tests use Python's standard library plus `tools/elf_index.py` and `tools/fde_extents.py`; they authenticate the input first, exclude `SHT_NOBITS` from file-byte mapping, do not invoke external programs, and never run the node.

```sh
python3 tools/artifacts.py verify
python3 tools/spot_index_unwind94.py --out <tmp-dir>/a
python3 -m unittest tests.test_spot_index_unwind94
python3 tools/catalogue.py --check
diff -r -x README.md -x MANIFEST.sha256 <tmp-dir>/a research/work-items/RE-006-spot-index-unwind-94
(cd research/work-items/RE-006-spot-index-unwind-94 && sha256sum -c MANIFEST.sha256)
```

Replace `<tmp-dir>` with a writable relative directory. To check output independence from hash seed and time zone, use two fresh directories:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/spot_index_unwind94.py --out <tmp-dir>/a
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/spot_index_unwind94.py --out <tmp-dir>/b
diff -r <tmp-dir>/a <tmp-dir>/b
```

`evidence.json`, `branches.tsv`, `calls.tsv`, `exception-sites.tsv`, `failure-routes.tsv`, `root-cases.tsv`, `split-cases.tsv` and `counter-cases.tsv` are generated. The manifest covers them and this README. Target coordinates and instruction bytes come from the ELF. The counter, root and split cases are expressly synthetic projections; their inputs are not claimed to be captured node states.

## Evidence

Addresses are linked ELF virtual addresses before load bias; intervals have exclusive ends. `evidence.json` retains full bytes, hashes and section-derived file offsets. For these selected `.text` ranges, file offset is VA minus `0x1000`. The collector binds each start and FDE record to `.eh_frame_hdr` and reads the end from `.eh_frame`. An FDE is an unwind-described extent, not a source-level function boundary or a complete function census.

| Selected role | FDE extent | Bytes |
| --- | --- | ---: |
| Slot-set search and delete entry | `0x2866e70..0x2866f81` | 273 |
| Outer user-keyed map split | `0x1a6caa0..0x1a6d917` | 3703 |
| Inner tagged-key set split | `0x1ade160..0x1adea8c` | 2348 |
| Cleanup wrapper A | `0x28ae330..0x28ae3bb` | 139 |
| Cleanup wrapper B | `0x2834030..0x28340bb` | 139 |
| Inner-set draining step | `0x2875a00..0x2875dc1` | 961 |

These six FDEs total 7563 bytes. Previously studied caller and search/entry bodies are used only through pinned call-site windows. The earlier `RE-006-price-level-lifecycle-94` and `RE-006-user-book-cancel-94` packets supply the slab and per-user context; the pending `RE-006-book-change-index-94` packet studies a different cancellation variant and its context-relative `+0x1320` index insertion. This packet's question is the spot path's failure and cleanup ordering, not a second selection of those bodies. The pending `RE-006-slot-repair-path-94` packet selects a different slot-deletion copy and its repair chain; this spot entry was previously considered but not selected there. Here its cursor repair remains outside the scope, and the entry is used to establish the gate to the subsequent index-failure path.

### Selected normal route

The bounded caller window saves a qword at `0x26de981`, supplies it to the previously researched slab-removal writer, and checks its result's low dword for 2. After the non-2 continuation it supplies the saved qword to the selected slot-set entry at `0x26dee86`. The connection between the saved qword and the later argument assumes intervening callees do not write through an alias to that stack slot.

The selected entry searches unsigned qword keys. Its header root, height and count are at `+0x00`, `+0x08` and `+0x10`; nodes use a u16 key count at `+0x62` and child pointers at `+0x68`. A null root or exhausted search returns zero without the entry's count decrement. A found key calls a separately scoped cursor at `0x1b22d70`, then, on normal return, decrements the qword at header `+0x10` without a separate zero guard before its root-shrink checks. The cursor's internal work is outside this packet.

| Post-cursor condition | Observed continuation |
| --- | --- |
| Output byte differs from 1 | Skip root shrink and return one. |
| Output byte equals 1 and root is null | Call the failure-shaped slot at `0x2866f62`, after the count decrement. |
| Output byte equals 1, root is nonnull and height is zero | Call a different failure-shaped slot at `0x2866f7b`, after the count decrement. |
| Output byte equals 1, root is nonnull and height is nonzero | Install child `+0x68` as root, decrement the header height, clear the new root's first qword, and pass old root and size `0xc8` to the relocation-bound release-shaped slot at `0x2866f45`; the continuation returns one. |

The output byte is initialized to zero before the cursor call. These are instruction-level paths and do not establish that malformed tree states are reachable, how the cursor sets the byte, the contracts of failure handlers, or what happens if a call does not return normally. The root-shrink path's read of the child pointer has no separate null check in this bounded sequence.

At `0x26dee92`, a zero return branches to `0x26df0a1`, bypassing the selected tracker decrement and changed-index insertion. A nonzero return falls through to a call with state-relative `+0x740`, then decrements the returned qword `+0x20` only if it is nonzero. `counter-cases.tsv` projects the guard across eight synthetic boundary cases, including zero and the unsigned maximum; it does not execute the target. The caller reads a root at state-relative `+0x8a0`; an absent user entry takes the outer entry wrapper, while the selected continuation passes tag 1 and the saved book word to the inner entry wrapper. The direct call sites and their targets are in `calls.tsv`; `spot_key_and_slab`, `spot_slot_gate`, `spot_counter`, `spot_map_root`, `spot_outer_handoff` and `spot_tag` retain the bounded bytes.

This is a conditional ordering statement. The slab-removal call and other earlier bookkeeping precede the slot-set return, and a missing slot-set key does not establish a side-effect-free cancellation. The tracker getter can have its own side effects. No result from the entry wrappers establishes final transaction success.

### Split geometry and root publication

The outer helper sees 20-byte keys at node `+0x110`, u16 count at `+0x1ee` and child pointers at `+0x1f0`. Its observed leaf and internal allocation sizes are `0x1f0` and `0x250`. The inner helper's 16-byte tagged keys use u16 count `+0xba` and children `+0xc0`; its corresponding sizes are `0xc0` and `0x120`. These are machine operands, not a recovered Rust ABI. `fields` in `evidence.json` extracts the offsets, allocation sizes and split thresholds from pinned instruction encodings.

Both helpers branch at 11 existing keys and compare insertion positions with 5 and 6. For a well-formed full node, the selected comparisons project to:

| Insertion gap | Promoted old-key index | New-key side | Left / right counts |
| --- | ---: | --- | --- |
| 0 through 4 | 4 | left | 5 / 6 |
| 5 | 5 | left | 6 / 5 |
| 6 | 5 | right | 5 / 6 |
| 7 through 11 | 6 | right | 6 / 5 |

`split-cases.tsv` constructs all 12 ordered synthetic examples. It checks the interpretation's ordering and counts; it does not run target instructions or establish all insertion paths.

On the selected root-growth paths, both helpers check the old root and allocate a new internal node. They initialize that node and place the old root in its first child slot before incrementing the old height. If the increment wraps, the branch occurs before the old root's parent or the tree header's root and height are changed. Otherwise, each updates the old root's parent, installs the new root and height in the header, and only then compares the saved height with another height value. A mismatch reaches a failure call after those stores. Whether an enclosing handler later rolls them back is not established. `root-cases.tsv` makes seven synthetic branch projections, including the unsigned maximum and one-less-than-maximum; no malformed state is asserted reachable.

### Exception records and cleanup

`failure-routes.tsv` binds eight selected conditional branches to their failure calls and the FDE-linked LSDA call-site interval. A blank landing means the decoded row has landing offset zero; it does not prove what a caller or runtime does. `exception-sites.tsv` retains all 33 call-site rows for the three selected FDEs with LSDAs, including raw ULEB bytes and action values. The action/type tables and runtime delivery are not decoded.

| Selected failure | Outer landing | Inner landing |
| --- | --- | --- |
| Leaf allocation failure call | `0x1a6d869` | no local landing in its decoded row |
| Root allocation failure call | `0x1a6d84c` | `0x1adea63` |
| Root-height increment overflow call | `0x1a6d83a` | `0x1adea51` |
| Post-publication height mismatch call | `0x1a6d86e` | no local landing in its decoded row |

For the two overflow calls, **if** the error call unwinds to the recorded landing, the landing passes the newly allocated node and respectively `0x250` or `0x120` to the same relocation-bound release-shaped slot and then reaches `ud2`. A normally returning overflow handler also leads to `ud2` in the selected code. This establishes the static paths, not that the handler actually unwinds or that these invalid heights occur in a valid book.

The outer mismatch call's landing calls cleanup wrapper A on a saved stack object and then reaches a resume-shaped external call. The inner mismatch call has no landing in its own decoded call-site row. This difference is a property of these FDEs and metadata; it is not a claim that inner unwinding performs no cleanup elsewhere. Root-allocation failure landings at both levels start with `ud2`. The error, release and resume functions' full contracts are not analyzed.

The two cleanup wrappers each initialize an iterator-shaped state from a three-qword tree header and call the same drain step at least once, including when the root is null. Each repeats while the returned leading word is nonzero. The drain step uses a remaining-count word, a `+0xba` node count, `+0xb0` parent links and `+0xc0` child links. On selected release paths it supplies `0xc0` for zero height and `0x120` otherwise. Its other malformed-state and traversal paths are not exhaustively proved. The 139-byte wrappers differ only inside the explicitly recorded four-byte relative-call operand; after masking bytes `[119,123)` their hashes agree, and the two actual call operands independently resolve to the same drain step. The mask is solely for this target-to-target comparison and does not establish helper, relocation, vtable or whole-ELF identity.

The three relative slots used by selected allocation, failure and release instructions, and the two additional selected failure slots, are bound to their ELF `R_X86_64_RELATIVE` records in `evidence.json`. These are static relocation addends, not proof of runtime loader resolution or allocator semantics.

### Inferences and unknowns

The prior book packets support calling the saved qword a slot index and the 20-byte key a user. The labels changed-user and changed-asset index are interpretations of the call context and the nested layout; the byte flow alone does not recover the original names or establish every consumer. The outer and inner helpers are generic tree machinery and are not shown to be exclusive to books. The cursor's full deletion/repair behavior, counter getter, wrapper internals outside the pinned handoffs, allocator, error and cleanup callees, LSDA action tables and eventual transaction outcome remain open.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lock, compiler/linker flags, two-build comparison, target ABI, fixture execution, raw or normalized Rust-to-target bytes, helper/data/vtable closure and whole-ELF identity are not yet measured. No target bytes are transplanted into a reconstruction.

The comparison of the two cleanup wrappers masks only the one four-byte call displacement described above. All original bytes and the actual decoded call targets remain in the evidence. Synthetic counter, split and root projections are independently checked for ordered output and selected state-write consequences, but are not target execution or a behavioral differential test. Negative controls alter the digest, FDE and unwind index, every selected body and witness, all selected conditional opcodes and displacements, each direct and RIP-relative call operand, relative relocations, LSDA encodings, and unmapped or NOBITS addresses.

## Results and limitations

The selected denominator is six FDEs totaling 7563 bytes, 22 fixed windows, 55 selected branches, 21 direct transfers, 18 RIP-relative sites, two register-indirect calls, five relative relocation records, three LSDA tables with 33 call-site rows, eight selected failure routes, 12 synthetic split examples, seven synthetic root examples and eight synthetic counter examples. These are scoped evidence counts, not node or component function coverage. The focused suite has 25 tests with no skips. Two generations with different hash seeds and time zones are byte-identical. Artifact verification and catalogue checks are reported in the draft; the repository-wide suite was not run under the memory constraint.

No component completion gate is requested. Next question: establish the original source and lifetime of the two height values on the spot path, and the caller-level effect of a real, authorized offline failure fixture after an index root has been published.
