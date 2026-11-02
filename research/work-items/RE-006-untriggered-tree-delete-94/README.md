# RE-006: untriggered-order tree deletion in node #94

A cancellation can delete a user's untriggered-order entry by replacing an internal key with its predecessor, repairing an underfull node, and contracting an empty root; the byte-backed layout and branch conditions here make that previously opaque removal step reconstructable.

- Component ID: `orderbook` (RE-006, one cancellation subpath).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred reference is unlicensed and was used only to choose the work area, not as implementation or evidence.
- Claim status: machine-code bytes, direct branch destinations, FDE records, dynamic relocation entries, and embedded diagnostic bytes are observations. The user-state and order-ID names are inferences qualified below. The projections are arithmetic consequences of selected conditions, not target executions.
- Scope included and excluded: the selected per-user tree deletion, its cursor, leaf repair and two rotations, including corresponding copies. Upstream cancellation bodies are context only and were previously studied; value creation, complete event/status effects, allocation behavior, unwinding effects, and other map types are excluded.

## Reproduce

Run from the repository root with the captured artifact present. The collector and its test use Python's standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. They do not invoke a disassembler, launch the captured program, or access the network. The collector verifies the input digest before parsing. This record was prepared on Linux x86-64 with Python 3.12.3; GNU objdump 2.42 was used only for manual instruction-boundary inspection. Its text is not a generated input.

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/untriggered_tree_delete94.py --out research/work-items/RE-006-untriggered-tree-delete-94
python3 -m unittest tests.test_untriggered_tree_delete94
PYTHONHASHSEED=0 TZ=UTC python3 tools/untriggered_tree_delete94.py --out '<tmp-dir>/a'
PYTHONHASHSEED=7 TZ=Pacific/Honolulu python3 tools/untriggered_tree_delete94.py --out '<tmp-dir>/b'
diff -r '<tmp-dir>/a' '<tmp-dir>/b'
PYTHONHASHSEED=123 TZ=Europe/London python3 -O tools/untriggered_tree_delete94.py --out '<tmp-dir>/optimized'
diff -r '<tmp-dir>/a' '<tmp-dir>/optimized'
```

Replace `<tmp-dir>` with a writable temporary directory. Each comparison output contains only the thirteen generated evidence files; none includes this README or the manifest. `MANIFEST.sha256` records the hashes of all packet files other than itself. The same regeneration and tests were also run with a Python-only `PATH` containing no binutils.

## Evidence

All addresses below are linked ELF virtual addresses; FDE ends are exclusive. `functions.tsv` gives the corresponding section-derived file offsets and actual `.eh_frame` records. Each selected FDE is also checked against `.eh_frame_hdr`. An FDE is an unwind range, not proof of a source boundary or a complete function census.

The [earlier user-state packet](../RE-006-prune-book-user-states-94/README.md) associates the book's user map with `+0xb8` and its per-user field at `+0x38` with the serialized field `u`. The [user-cancellation packet](../RE-006-user-book-cancel-94/README.md) identifies that field's u64 keys and records cancellation calling a removal routine. The [trigger-order packet](../RE-006-trigger-order-fire-94/README.md) identifies the entries as untriggered orders and leaves tree-removal helpers outside its examined bodies. This packet studies previously unexamined deletion helpers, using three **call sites**, rather than reanalysing those existing caller functions. At `0x42f8954`, `0x26de5a4`, and `0x26df5fa`, the surrounding pinned bytes pass the user-state result plus `0x38` and a pointer to a key to the respective new entry. The first site lies inside a previously mapped cancellation-removal body in the cited user-cancellation packet; the two spot sites lie inside removal bodies listed in the [order-modify packet](../RE-006-order-modify-path-94/README.md). Those enclosing FDEs are context, not newly selected subjects. The caller windows and the exact rel32 call bytes are retained in `anchors.tsv` and `calls.tsv`. The [order-placement packet](../RE-006-order-place-route-94/README.md) reports that the corresponding user-state accessor can create an entry. This packet does not reanalyse that accessor, so a missing tree key does not establish that the enclosing cancellation made no other change.

| Selected role | Entry points | FDE bytes each |
| --- | --- | ---: |
| Search and remove | `0x49454a0`, `0x2866870`, `0x28660a0` | 883 |
| Remove selected cursor | `0x42b66c0`, `0x1b22a90` | 730 |
| Delete from leaf and repair | `0x429f690`, `0x1b17160` | 3248 |
| Transfer from left sibling | `0x42788d0`, `0x1af72d0` | 839 |
| Transfer from right sibling | `0x427ecd0`, `0x1afcfe0` | 958 |

The selected edges form a connected path: the remove entries call their matching cursor, each cursor has a direct leaf arm and an internal-key arm that both call its matching leaf helper, and each leaf helper calls its matching two rotation helpers. The 18 listed calls include the three external context sites and selected internal edges; they are not an exhaustive whole-binary caller census.

### Layout and search

The byte-selected offsets in `constants.tsv` describe the following representation. Offsets are relative to the pointer or node named in the table.

| Object | Offset | Observed use |
| --- | ---: | --- |
| Book | `+0xb8` | Passed to a user-state accessor in the context windows. |
| Returned user state | `+0x38` | Address passed as the tree header. |
| Tree header | `+0x00`, `+0x08`, `+0x10` | Root, height, and entry count; a successful removal decrements the count. |
| Tree node | `+0x00`, `+0x848`, `+0x84a`, `+0x850` | Parent pointer, 16-bit parent index, 16-bit key count, and child pointers. |
| Tree node keys | `+0x08`, stride 8 | Compared as unsigned u64. |
| Tree node values | `+0x60`, stride `0xb8` | Selected value, shifted together with its key. |

The selected offsets and decoded address scales leave room for eleven key strides, eleven value strides, and twelve internal edge strides, as calculated in `layout-capacity.tsv`. Those region boundaries and the internal allocation interpretation are inferences supported by the offset layout and the recorded capacity assertions; they are not a recovered Rust type declaration.

The search compares keys in ascending unsigned order. A null root or descent beyond height returns the first output word `2` without decrementing the tree count. An equal key calls the cursor, after which the header count is decremented. If the removed value's first word is itself `2`, the wrapper also returns word `2` after the deletion; the meaning and validity of such a stored value are not established here. The wrapper compares the full first qword with `2`; the pinned caller continuation compares only its low dword. These widths differ for projected words with nonzero high bits; whether such a value can occur in a valid book is unresolved. This distinction matters when specifying the output tag and the state mutation.

A short human-readable excerpt, with bytes preserved by the collector:

```text
49454d0  read 16-bit node count at +0x84a
49454f5  compare requested u64 with the next node key
4945515  branch to the equal-key path
4945562  call the selected cursor
4945619  decrement the header count at +0x10
```

### Cursor, repair, and failure branches

| Condition | Observed path |
| --- | --- |
| Found cursor height is zero | Call the leaf deletion helper on the selected key. |
| Found cursor height is nonzero | Follow the selected child, then rightmost child pointers to a leaf; delete its last key and move that predecessor key/value into the selected internal position. |
| Leaf has more than four keys after deletion, or has no parent | Return the removed key/value without entering sibling repair. |
| Leaf has at most four keys and has a parent | Use a left sibling when the parent index is nonzero, otherwise use the right sibling. If the old leaf count plus sibling count is at least twelve, call the corresponding one-entry transfer; otherwise enter the merge path. The old leaf count equals the remaining count plus one on this path. |
| Merged parent remains underfull | Repeat repair toward its parent. A reached root with count zero sets the flag consumed by the wrapper. |
| Root-contraction flag is set | Require a non-null root and nonzero height, move child zero to the root field, decrement height, clear its parent pointer, and call an indirect slot with the old root, size `0x8b0`, and zero as arguments. The deallocation role is inferred from that calling pattern. |

The two rotation helpers check the destination length plus requested count against the exclusive limit twelve and check that the donor has at least the requested count. They change the two 16-bit lengths, transfer the parent separator and values, and shift key/value arrays. If both child sides have nonzero height, child pointers and their parent/index fields are updated; if exactly one has zero height, a diagnostic path is selected. The upward repair path can request `5 - current_count` entries, while the immediate underflow path requests one. In each rotation, capacity and donor checks precede the count stores, while the side-height mismatch check occurs after those stores and the parent key/value transfers. The tree-header count is likewise decremented before the root-contraction checks. These are observed instruction orderings; the effects retained after an error or unwind are not established.

`branches.tsv` records selected conditional sites, exact encodings, and taken/fallthrough addresses. `boundary-cases.tsv` projects ten comparisons around the constants read from the ELF: in particular, merged totals 11 and 12 fall on opposite sides of the branch. These are mathematical cases, not executions of node instructions. They assume well-formed tree and cursor inputs; malformed pointers and arbitrary corrupted lengths are not modeled.

`diagnostics.tsv` binds ten selected error paths to bytes and `R_X86_64_RELATIVE` Location records. It includes root-height, destination-capacity, donor-length, tracked-edge and copy-length assertions, plus both side-height mismatch diagnostics. Full embedded build paths are hashed and only their relative suffixes are retained. Location records identify diagnostic provenance, not the source function boundary or original first-party source. `failure-edges.tsv` and `failure-locations.tsv` additionally record the null-root and empty-internal error call sites and their Location records without guessing the latter helper's encoded argument. The dynamic relocations for two selected memory operation slots identify `memcpy` and `memmove`; four selected internal slots are recorded by relocation type and addend without assigning function names. These are listed separately in `relocations.tsv`.

### Copy comparison

`masked-operands.tsv` records every masked field and its independently resolved target. The search, cursor, leaf, left-transfer, and right-transfer families mask respectively 9, 5, 33, 17, and 13 four-byte PC-relative operands per body. The tool validates the opcode immediately before each field and masks no conditional branch displacement, member offset, ordinary immediate, or opcode. Across the six selected peer-to-reference copy pairs, raw equal is 0, masked-only equal is 6, and unmatched outside the declared masks is 0. These are comparisons among captured-code copies, not rebuilt functions or a whole-node denominator. Raw hashes and raw differing-position counts remain in `functions.tsv` and `evidence.json`. Masked equality is a local code-shape observation: different call targets and referenced data remain separate questions, and a test explicitly shows why equal masked bytes do not imply equal call destinations.

### Inferences and unresolved points

The `user_states`, `u`, and untriggered-order labels use the cited serializer evidence; the key is called an order ID because of the cited cancellation and trigger-path evidence. The selected bytes alone prove only the offset, unsigned key and copied value shapes. Spot/perpetual labels for the context windows follow prior packet attribution, not these helper bytes alone.

The handling of the removed value after return, ownership of indirect slots other than the two named memory operations, diagnostic side effects, and every possible corrupt tree state remain unresolved. The parent and child invariants required by the low-level helpers are assumptions, not established safety checks. No claim is made that these routines cover every route that cancels an order.

## Implementation and comparison

Rust implementation: not yet implemented. No Cargo lock, compiler/linker flags, independent build, two-build result, target behavior comparison, or reconstructed-body comparison is available for this packet.

The thirteen generated files are `functions.tsv`, `anchors.tsv`, `constants.tsv`, `layout-capacity.tsv`, `branches.tsv`, `boundary-cases.tsv`, `failure-edges.tsv`, `failure-locations.tsv`, `calls.tsv`, `masked-operands.tsv`, `diagnostics.tsv`, `relocations.tsv`, and `evidence.json`. The collector checks 41 exact windows, 18 selected direct calls, 94 selected branches, and 10 diagnostic records. The 13 unit tests include a corrupted target hash, altered pinned bytes and opcode, changed masked call target, invalid branch/call encodings, out-of-range and NOBITS mappings, duplicate/missing relocations, and boundary arithmetic fixtures. The arithmetic fixtures check a separate checked model only; they do not execute target code.

## Results and limitations

The collector reproduced all thirteen evidence files under different hash seeds and time zones with no differences, including a third run with Python optimization enabled. The focused suite passed 13 tests with no skips; artifact verification and the catalogue check passed. Imported-source verification also passed when Git LFS temporary storage was redirected to a writable directory. Its initial default invocation failed because the sandbox makes the Git LFS temporary metadata read-only; no submodule or imported input was changed.

This is a bounded static packet, not the full RE-006 acceptance gate. Helper/indirect-call closure, runtime behavior, allocation and panic side effects, relocations beyond the six selected slots, vtables, whole-program data, and whole-ELF equivalence remain unmeasured. No progress gate is requested.

Next question: trace the returned `0xb8`-byte value through the already identified cancellation branches and establish which field/tag decides event construction, using new non-overlapping function bodies and a separately authorized behavior harness if execution becomes necessary.
