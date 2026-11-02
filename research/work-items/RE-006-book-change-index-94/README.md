# RE-006: cancellation change-index insertion on node 94

This packet establishes how a cancellation records a changed user and asset in two nested trees, including the different layouts, duplicate handling, split propagation, failure branches and a text-field binding needed to reconstruct that bookkeeping path.

- Component ID: `orderbook`, task RE-006 (book cancellation).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; unlicensed reference `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a lead.
- Claim status: selected FDE ranges, ELF records, exact byte windows, table entries and branch targets are observations. Names of records, the insertion projections and their relation to book state are inferences, qualified below. Unwind effects and runtime reachability remain unresolved.
- Scope included and excluded: five previously unrecorded FDEs for an outer vacant-entry counterpart, the cancellation-context outer split helper, the inner split helper, an inner comparator/search counterpart and a related text-field helper. Previously studied cancellation, slot-set removal, user lookup and inner-set entry bodies are bounded context or called edges, not selected FDEs. Full cancellation, settlement, the other entries of the changed set, other markets and the action-table semantics are excluded.

## Reproduce

From the repository root with Python 3.12.3 on Linux x86-64 and the authenticated target in the artifact location:

```sh
python3 tools/artifacts.py verify
python3 tools/book_change_index94.py --out '<tmp-dir>/a'
python3 -m unittest tests.test_book_change_index94
python3 tools/catalogue.py --check
diff -r -x README.md -x MANIFEST.sha256 '<tmp-dir>/a' research/work-items/RE-006-book-change-index-94
```

Replace `<tmp-dir>` with a writable relative directory. A second regeneration under another hash seed and time zone can be compared without requiring binutils:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/book_change_index94.py --out '<tmp-dir>/a'
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/book_change_index94.py --out '<tmp-dir>/b'
diff -r '<tmp-dir>/a' '<tmp-dir>/b'
```

The collector authenticates the complete binary before parsing; it uses the shared ELF/FDE/ULEB readers, excludes NOBITS from file mappings, and starts no external process. GNU objdump 2.42 was used only for human inspection, and no disassembler output enters a generated file or a test. The node and visor are never executed. `MANIFEST.sha256` covers this README and all generated evidence files.

## Evidence

Addresses are linked ELF virtual addresses and ends are exclusive; `functions.tsv` records the corresponding file offsets, exact bytes, FDE/CIE/LSDA coordinates and SHA-256 digests. An FDE is an unwind extent and does not itself prove an original source-function boundary.

| Selected role | FDE extent | Bytes |
| --- | --- | ---: |
| Outer vacant-entry counterpart | `0x4959950..0x4959abe` | 366 |
| Outer insert and split | `0x4205930..0x42067a7` | 3703 |
| Inner insert and split | `0x4223660..0x4223f8c` | 2348 |
| Inner-entry search counterpart | `0x33a0780..0x33a094d` | 461 |
| Related text-field helper | `0x47abcf0..0x47abdb9` | 201 |

The 7079 selected bytes are retained without normalization. The previously studied cancellation FDE `0x42f7890` is context; only the fixed windows and edges in `windows.tsv` and `calls.tsv` are examined here.

### Cancellation branches and the handoff

The entry saves the book, user pointer and order key. It calls the previously studied removal from the user's `+0x38` tree and compares the low **32 bits** of the returned first word with `2`. A result whose low dword is not 2 goes through the first bookkeeping branch. With low dword 2, a hash miss exits this selected route; a hash hit saves a slot key and calls the existing slab-removal helper. A slab result whose low dword is 2 exits; another value reaches the user's set at entry `+0x20`.

At `0x42f828e` the saved key is passed to the existing set-removal entry. Its false result takes `0x42f82a4 -> 0x42f84b9`, bypassing the following bookkeeping but continuing into the already studied unlink code. Its true result enters the bookkeeping. This does **not** mean that the failed-set path is side-effect-free: earlier lookups, removals or entry creation can have occurred. Linking the saved qword to the same slot key across intervening calls assumes no callee writes that stack slot through an alias.

Both the first bookkeeping branch and the successful slot-set branch pass a 20-byte user to the existing helper at `0x47d7ca0`, then decrement its returned qword at `+0x20` only when nonzero. The second branch reads the qword at book `+0xb0`, and searches the tree rooted at exchange state `+0x1320`, with height at `+0x1328`. The search compares 20-byte keys using the relocation-bound `memcmp` slot. A match uses the existing 24-byte value; a miss constructs a vacant entry and calls `0x495a170`. Both cases then pass value pointer, tag `1`, and the book qword to the existing inner-set entry. The first bookkeeping branch uses the same tag and also gets the book qword before its corresponding call. The first and third qwords of the empty inner header are set to zero in the captured window; this window does not establish the middle qword's value while the root is null.

The caller's tag-2 comparisons are dword tests, while the complete values and their valid high bits are unresolved. `synthetic-routes.tsv` illustrates the branch consequences, including high-bit controls, assuming the intervening callees return normally; it is a projection, not a target run. The prior `RE-006-trigger-order-fire-94` packet identifies the helper used for inner-set entry, and the existing lifecycle and user-cancel packets provide the book and user context.

### Two tree layouts

| Property | Outer user-keyed map | Inner tagged set |
| --- | --- | --- |
| Entry payload | 20-byte key; 24-byte value at node `+0x08`, stride `0x18` | two qwords per item, stride `0x10` |
| Key array | node `+0x110`, stride `0x14` | node `+0x00`, stride `0x10` |
| Parent and edge index | node `+0x00` and u16 `+0x1ec` | node `+0xb0` and u16 `+0xb8` |
| Key count and edges | u16 `+0x1ee`, child pointers `+0x1f0` | u16 `+0xba`, child pointers `+0xc0` |
| Leaf / internal request | `0x1f0` / `0x250` bytes | `0xc0` / `0x120` bytes |
| Key capacity | 11 | 11 |

The cancellation-context entry `0x495a170` was already named by earlier work and is not a selected FDE. Its direct call reaches `0x4205930`. The newly selected outer counterpart allocates a leaf when its cursor node pointer is null; otherwise it passes the cursor, key and value to a different split helper. Its resulting node, index and header pointer identify the nested value. The 366-byte context and counterpart bodies have 21 different bytes, all inside 11 recorded PC-relative fields; after masking those 44 bytes they are identical. `outer-copy-operands.tsv` resolves each operand: the split and two cleanup call targets differ, while the remaining listed targets agree. This comparison establishes the shared unmasked byte shape, not equality of the different callees or their effects. On a new entry it increments the map count at header `+0x10` using a qword `inc`; wrap at `u64::MAX` is a machine-level consequence, not a demonstrated valid-state case.

For the inner entry, the independently selected counterpart has 461 bytes. Against the cancellation-context entry there are 27 differing bytes, all inside seven explicit four-byte PC-relative fields. After masking those 28 bytes the bodies are equal; `copy-operands.tsv` resolves every field independently. The split helper and source-location target differ, and the jump tables are at different addresses. Each table's four entries lead to its own counterpart's same comparison arm. This is an exact, limited comparison of those body bytes and table destinations, not a claim that the different helpers or diagnostic locations are equivalent.

In the common comparison arm for tags 0 through 3, equal tags compare the second qword unsigned. The cancellation passes tag 1. A matching pair returns 1 without an insertion; after successful insertion a new pair returns 0 after incrementing the inner header count. The selected cancellation call sites do not test that return before later work. Other tag values, and how the changed set is later consumed, are outside this packet.

### Split and error decisions

Both selected split helpers use the following rule for a full node, where `position` is the insertion point among the old 11 keys:

| Position | Promoted old index | Inserted side | Resulting left / right key counts |
| --- | ---: | --- | --- |
| 0..4 | 4 | left | 5 / 6 |
| 5 | 5 | left | 6 / 5 |
| 6 | 5 | right | 5 / 6 |
| 7..11 | 6 | right | 6 / 5 |

`constants.tsv` extracts the capacity, thresholds, pivot immediates, selected offsets and allocation sizes from checked instruction encodings. `synthetic-splits.tsv` enumerates all 12 positions for each layout. A full parent repeats the same decision, copies child pointers, and writes moved children's parent and parent-index fields. A root split allocates a new internal node, links the old root, raises height, and installs the promoted entry and sibling. These conclusions assume a well-formed tree and successful allocation.

`failure-edges.tsv` lists 28 selected insertion failure branches, including null allocation, capacity, sibling/edge bounds, height disagreement and height overflow, plus two text-field control branches. The diagnostic bytes identify the edge-height, equal-length and capacity assertions. In both root paths the height-disagreement test comes **after** stores installing the new root and height; the packet therefore does not infer rollback from a failure edge. Three selected FDEs have exception tables: `lsda-headers.tsv` and `lsda-call-sites.tsv` retain 36 decoded call-site ranges and landing-pad coordinates. The counterpart and text-field helper have no LSDA. Action/type tables and the effects of executing a landing pad are not decoded. The list is a selected branch inventory, not a complete CFG.

### Related text-field binding

A separate formatter-shaped FDE passes a pointer at its object `+0x1320` to selected helper `0x47abcf0` at `0x46f636f`. When the helper's first input byte is zero, it passes the three exact bytes `uaR` to a key-writing call, appends colon and space after a capacity check, and passes the saved field pointer to a value-writing call. A nonzero input flag bypasses the key-writing path; an assertion and a capacity-growth path are separately pinned. The nested value writer is outside scope. The supplied reference lists the similar trailing field as `uar`; the differing case is observed in the target literal, while the complete correspondence between that reference field and this object remains an inference.

The equal offset and neighboring state offsets make this relevant to the cancellation map, but the separate call sites do not prove that the two pointers name the same runtime object. In particular, this is not evidence that the accumulated changes are drained or that the complete serialized representation is known.

### Inferences and unknowns

The qword from book `+0xb0` is an asset and the 20-byte key is a user by the prior book and trigger packets. The observed register flow, byte widths and comparisons do not recover original Rust type names. The nested set represents changed `(tag, asset)` items by its caller and existing trigger evidence; it is not proven that a later consumer processes every inserted item, or that tag 1 has the same meaning outside this call path. The user counter helper is an external get-or-insert operation in earlier evidence, so its own allocation and initialization side effects are not reproduced here.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lock, compiler/linker flags, raw and normalized Rust-to-target comparisons, relocation/vtable closure, unwind runtime behavior and target-executed boundary fixtures are **not yet measured**. The only normalizations mask the 11 outer and seven inner enumerated PC-relative fields when comparing each target counterpart with its context; raw selected bodies and every resolved target are retained. No captured target code was executed.

The focused tests attack digest, FDE binding, NOBITS and invalid address ranges, every selected window, direct-call displacement, branch opcode, immediate, relocation field, diagnostic byte, both table encodings and LSDA bounds. They also check all 12 split positions and three 1021-key synthetic multilevel insertion sequences against independent sorted-key and tree-shape invariants. Those models check this interpretation; they are not target behavior comparisons.

## Results and limitations

The retained selection has 5 FDEs (7079 bytes), 30 byte windows, 102 selected conditional branches, 16 direct calls, 18 RIP-relative indirect calls, one RIP-relative pointer load, seven relocation records, four literal records, eight table entries, 36 exception call-site records, 24 synthetic split rows and nine synthetic route rows. These counts are a selected-evidence denominator, not a whole-component coverage measure. The focused suite has 29 tests and no skips.

No progress gate is requested. Unresolved items include the saved-key alias assumption, all allocator and indirect-helper internals, valid value tags and high bits, rollback and exception effects, the outer map's other writers and consumers, and complete RE-006 behavior. Next question: trace the consumer of the `+0x1320` map to determine how `(tag 1, asset)` differs from other tagged entries when the accumulated changes are drained.
