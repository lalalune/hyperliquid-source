# RE-006: book user-entry insertion, node splitting and order queue on node 94

This packet establishes how a resting-order path finds or creates a 20-byte-keyed book user entry, propagates full-node splits to a new root, and conditionally appends the selected order key to a growable circular queue; these rules allow the user-state insertion path to be reconstructed with the correct split and queue-wrap decisions.

- Component ID: `orderbook` (RE-006, book state transitions).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is unlicensed and supplies leads only; no reference implementation is copied or treated as authority.
- Claim status: selected bytes, FDEs, call displacements, relocations and diagnostics are observations. Data-structure roles, user identity and the split model are inferences from those observations. Reachability and the unresolved fields below remain unknown.
- Scope included and excluded: the lookup/entry routine, vacant-entry insertion wrapper, node insertion/split body, queue append and wrapped-buffer growth, plus a bounded resting-order caller context. The external slot writer, per-entry set insertion helper and backing allocator are not analyzed here. This is not the nested per-user order-index deletion studied in the open user-index-delete packet, nor a whole order matcher.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3 or a compatible Python 3. The generator requires only the Python standard library, `tools/elf_index.py`, `tools/fde_extents.py`, and the authenticated target. It validates the complete input digest before reading ELF records, excludes `SHT_NOBITS` from file-backed VA translation, and invokes no external program. No captured binary, network, key or chain action is executed. GNU objdump 2.42 was used only to inspect instruction boundaries and prepare the human excerpt below; it is not a generator or test input.

```sh
python3 tools/artifacts.py verify
python3 tools/book_user_entry94.py --out research/work-items/RE-006-book-user-entry-94
python3 -m unittest tests.test_book_user_entry94
python3 tools/catalogue.py --check
(cd research/work-items/RE-006-book-user-entry-94 && sha256sum -c MANIFEST.sha256)
```

Use a fresh relative scratch location in place of `<tmp-dir>` to check output independence from hash seed and time zone:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/book_user_entry94.py --out <tmp-dir>/a
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/book_user_entry94.py --out <tmp-dir>/b
diff -r <tmp-dir>/a <tmp-dir>/b
diff -r -x README.md -x MANIFEST.sha256 <tmp-dir>/a research/work-items/RE-006-book-user-entry-94
```

`functions.tsv` and `function-bytes.tsv` retain full selected bodies and hashes. `witnesses.tsv` retains the selected semantic windows; `calls.tsv`, `branches.tsv`, `indirect-references.tsv`, `relocations.tsv` and `failure-diagnostics.tsv` retain the selected edges and error evidence. `initial-value.tsv` records only writes actually identified in the value-construction sequence. `split-cases.tsv` and `queue-growth-cases.tsv` are synthetic interpretations of the position and circular-buffer rules, and `evidence.json` states their counts. `MANIFEST.sha256` hashes every other file in this folder.

## Evidence

Coordinates below are linked ELF virtual addresses, and ranges are half-open. The file offsets are resolved from the ELF section headers, rather than a presumed mapping. For these code ranges the file offset happens to be VA minus `0x1000`. An FDE is an unwind-described extent, not a complete symbol census or a source-level function boundary.

| Inferred role | FDE range | Body bytes | Relevant caller or callee |
| --- | --- | ---: | --- |
| Find or create user entry | `0x25a7730..0x25a78d6` | 422 | called at `0x26ee02f` |
| Insert vacant entry | `0x287ae20..0x287aff0` | 464 | called at `0x25a78aa` |
| Insert into node and split | `0x1a9a820..0x1a9bc1a` | 5,114 | called at `0x287ae7e` for a non-null node |
| Append to user queue | `0x2517560..0x25175b2` | 82 | called at `0x26ee0bb` on the conditional path |
| Grow and rearrange wrapped queue | `0x3438fc0..0x343904a` | 138 | reached through the relocated slot at `0x2517579` |

The selected bodies total 6,220 bytes. Their FDE, CIE and optional LSDA coordinates, complete original bytes and SHA-256 hashes are generated from the ELF. The generator verifies all five whole-body hashes and 27 further byte windows. The 36 branch records are selected instruction sites, not a claim to have found every branch.

### Binding to a resting-order insertion

At `0x26ebdda..0x26ebde2` the caller saves its incoming book-shaped pointer from `rsi`. The context at `0x26ec0f7..0x26ec126` takes a 20-byte key from the incoming record at `+0xb8`. At `0x26edf1d..0x26edf95`, the value returned by a preceding writer is saved, placed into a head/tail-shaped link, and an existing neighbor is checked with stride `0xf8` and vacant discriminant 2. The later window `0x26edfff..0x26ee045` passes book `+0xb8` and that 20-byte key to the entry routine. It then passes the returned entry `+0x20` together with the saved writer result to an external helper. The caller initially stores the byte read from order `+0x90` in a stack slot. The later window `0x26ee079..0x26ee0c0` tests that slot and, when it is nonzero, repeats the lookup for the same key and passes the resulting entry and selected order key to the queue append. The earlier windows `caller-id-input`, `caller-id-select` and `caller-id-save` retain the key selection. These are static observations of selected caller windows; the writer and set-helper bodies are outside this packet. The windows alone do not rule out an intervening write through an alias to either saved stack value.

This binds the selected tree to the resting-order context without claiming that every insertion takes the same route. The earlier `RE-006-order-place-route-94` packet also uses a user-entry tree but leaves different split helpers stubbed. The open user-index-delete packet addresses the *nested* `entry+0x38` tree keyed by eight-byte order identifiers. Its selected FDEs are distinct from the three above.

### Search and initial value

The entry routine reads the root and height from the tree header at `+0x00` and `+0x08`. At each node it reads a u16 live count at `+0x456`; it compares only those keys, in order, with 20-byte `memcmp`. The imported symbol and slot are backed by the dynamic relocation in `relocations.tsv`. A positive result advances, equality returns the associated value, and a lesser key or exhausted node selects the corresponding child if height remains. A null root or exhausted height takes the vacant-entry path. Thus equality does not create or overwrite a value in this routine.

The returned pointer is the node address plus the key index times `0x50`. A newly constructed 80-byte value has these identified writes, relative to that value:

| Value offset | Width | Written value |
| --- | ---: | ---: |
| `+0x00` | 8 | 0 |
| `+0x08` | 8 | 8 |
| `+0x10` | 16 | all zero |
| `+0x20` | 8 | 0 |
| `+0x30` | 16 | all zero |
| `+0x48` | 8 | 0 |

The construction sequence does not define `+0x28..+0x2f` or `+0x40..+0x47` in the selected writes. Do not infer those bytes are zero. Names, validity rules and later uses of the value fields are not established by the default stores alone.

### Node layout and insertion

| Node offset | Observed use |
| --- | --- |
| `+0x000` | eleven value slots, stride `0x50` |
| `+0x370` | parent pointer |
| `+0x378` | eleven key slots, stride `0x14` |
| `+0x454` | u16 parent-edge index |
| `+0x456` | u16 live-key count |
| `+0x458` | up to twelve child pointers in an internal node |

The sizes implied independently by the operands are `0x458` bytes for a leaf allocation and `0x4b8` bytes for an internal allocation. On an empty tree, the insertion wrapper allocates the former, sets a null parent and zero key count, installs it as root with height zero, writes the first key and value, and increments the header qword at `+0x10`. The increment is unconditional after the lower insertion returns; no overflow check is shown in this selected sequence. Valid-state bounds on that counter are unresolved.

For a non-full leaf, the node routine shifts later keys and values separately, writes the incoming pair at the selected position and increments the node's u16 count. The identified overlapping-shift slot resolves to the imported `memmove`; the split-copy slot resolves to `memcpy`. The helper called for a nonempty node returns the selected node and position to its wrapper, which increments the tree count once and returns a cursor. The entry routine then computes the pointer to the inserted value.

### Full-node split decisions

On a valid full node with 11 old keys, the bytes at `0x1a9a84c..0x1a9a902` and `0x1a9aa6a..0x1a9aa85` choose an old key to promote before the new pair is inserted. The parent-split arm repeats the position tests at `0x1a9b090..0x1a9b260`.

| Incoming insertion position | Promoted old-key index | Insert into | Resulting left / right key counts |
| --- | ---: | --- | --- |
| `0..4` | 4 | left, original position | 5 / 6 |
| `5` | 5 | left, position 5 | 6 / 5 |
| `6` | 5 | right, position 0 | 5 / 6 |
| `7..11` | 6 | right, position `position - 7` | 6 / 5 |

For example, an incoming key at position 5 promotes old key 5 and goes to the end of the left node. At position 6, the same old key is promoted and the incoming key goes to the start of the right node. The 12 rows in `split-cases.tsv` use synthetic keys solely to make this reading checkable. They are not execution results from node #94.

Human-reading excerpt, with addresses and instruction text inspected using GNU objdump; this text is not parsed by the tool:

```text
1a9a84c  cmp    r13, 0xb
1a9a862  jb     1a9a884
1a9a868  cmp    r13, 0x5
1a9a86c  jae    1a9a8f8
1a9a877  mov    r13d, 0x4
1a9a8f8  je     1a9aa6a
1a9a8fe  cmp    r13, 0x6
1a9a902  jne    1a9aa73
1a9aa73  add    r13, -7
1a9aa7c  mov    r13d, 0x6
```

After the leaf split, a non-full parent receives the promoted key/value and a right-child pointer. The code moves later entries and edges and updates affected children's parent pointers and u16 edge indexes. A full parent is split with the corresponding 4/5/6 pivot rule and propagation continues. When the split reaches a root without a parent, the code allocates an internal node, attaches the old root and new right child, installs the promoted pair, sets their parent/index fields, and increments the tree height. These statements are static control-flow interpretations, not runtime observations.

### Conditional queue append and wrapped growth

The conditional call uses the beginning of the same 80-byte user value. The append and growth bodies establish the following qword fields:

| Value offset | Observed queue role |
| --- | --- |
| `+0x00` | capacity in eight-byte elements |
| `+0x08` | allocation pointer |
| `+0x10` | head index |
| `+0x18` | live length |

These fields match the empty-value writes above: capacity, head and length are zero, while the initial pointer word is 8. At `0x2517571..0x2517579`, equal length and capacity calls the growth routine through a relocated pointer. On return, the append reloads capacity and length, increments length, and writes the key at `head + old_length`, subtracting capacity once if that sum is at least capacity. `0x2517594..0x251759b` is the compare and conditional subtraction; the value stride is eight bytes. The caller's nonzero order flag is the only entry gate shown here.

The growth body saves the old capacity, calls an external backing-storage growth helper, then reloads head and length; the wrapped branch also reloads capacity. For a full queue and a successful backing growth that preserves the old elements, head and length, write `high = old_capacity - head`, `low = length - high`, and `extra = new_capacity - old_capacity`:

| Condition after backing growth | Observed action |
| --- | --- |
| `head <= old_capacity - length` | no rearrangement |
| wrapped and (`high <= low` or `extra < low`) | `memmove` the high segment to `new_capacity - high`; set head to that index |
| wrapped, `high > low` and `extra >= low` | `memcpy` the low segment from index 0 to index `old_capacity`; keep head |

For example, a full six-element queue at head 2 has high/low lengths 4/2: a hypothetical new capacity 7 takes the first move, while capacity 8 takes the second. A full four-element queue at head 3 moves its one-element high segment. These examples and 507 synthetic combinations in `queue-growth-cases.tsv` assume a successful preserving allocator and do not claim it chooses the supplied capacities. The finite test domain covers old capacities 1 through 11, each valid head and hypothetical capacity increase 1 through the old capacity, plus one empty case. The bound 11 is a chosen test bound, not a maximum queue capacity. The base allocator's policy, allocation failure and effects are outside this packet.

The append uses 64-bit `lea`/`add` and one subtraction without a separate carry check. The mathematical circular-index description assumes a valid, representable queue state; for an overflowing `head + length` or malformed state, the instruction sequence alone does not establish modulo behavior or memory safety. The synthetic model rejects such inputs; that rejection is a model precondition, not a target guard.

### Error and boundary paths

The selected branch table and diagnostic strings distinguish:

- no root or a leaf search miss, which creates a value; an equal key returns the old value;
- allocation failure for the first leaf, split leaf, split internal node or new root;
- a node length not below 11 on a path requiring spare capacity, and split copy bounds beyond the recorded 11-key or 12-edge limits;
- unequal source and destination edge-copy lengths, and an ancestor or new-root edge-height mismatch; and
- a missing old root or wrapping height increment during root replacement.

`failure-diagnostics.tsv` contains five selected length-delimited assertion references, including the distinct height and copy-length texts. Other calls, cleanup/unwind edges and relocation targets remain outside this path's closure. No claim is made that corrupted-state paths are recoverable or that mutation has been rolled back before a failure.

### Inferences

The 20-byte key is a user identifier and the 80-byte value is the book's user state: the key comes from the order-shaped input, the tree is at book `+0xb8`, and the returned value supplies `+0x20` to the resting-slot index helper. The queue at `+0x00` is the per-user reduce-only order list: the prior perp-insert packet identifies the order flag with that role, and this caller tests the stack slot initially loaded from that flag; preservation along the full caller path remains an inference. The exact source names and types are not present in the selected symbol evidence. `memcmp` supplies bytewise ordering, not numeric ordering of a 20-byte integer. The parent/child interpretations follow the pointer and edge-index repairs and remain qualified as such.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lockfile, compiler/linker flags, independent two-build comparison, raw-equal/normalized-only/unmatched counts and normalization masks: **not yet measured**. This packet does not compare a Rust build with the target, establish helper closure, or claim whole-ELF equivalence.

The focused unittest suite checks the digest, FDE ranges, 27 independently pinned windows, all 36 selected branch conditions, five call displacements, 21 RIP-relative references, ten relocation slots, the initial-value writes and the assertion texts. Negative controls change the digest, FDE start, each selected branch condition and displacement, every selected window, each direct-call displacement, indirect displacement, initialization instruction, diagnostic text, a relocation type, symbol and executable addend; they also reject missing, non-file-backed and non-executable addresses.

A separately written synthetic tree model exercises all 12 split positions, duplicate keys, bytewise ordering and three multi-level sequences totaling 907 distinct insertions. It checks sorted key/value pairing, node occupancy, parent links, equal leaf depths and duplicate results against independent sorted-map expectations. Separate queue controls compare all 506 non-full small-capacity append indexes with mathematical modulo and check order preservation for 507 synthetic full-queue growth cases. It is a consistency check for the static interpretation, not execution, emulation, a target fixture, or proof of behavior for malformed state.

## Results and limitations

The export contains 5 FDEs, 6,220 full-body bytes, 27 selected windows, 36 selected branches, 5 direct edges, 21 indirect references, 10 relocation slots, 5 diagnostic references, 6 initial-value writes, 12 synthetic split rows and 507 synthetic queue-growth rows. These are bounded packet counts, not a denominator for all functions or all branches. The focused suite has 32 test methods and no skips; verification and deterministic regeneration results are recorded in the draft.

No progress gate is requested. The complete external order call chain, actual runtime reachability, backing allocator and panic semantics, exhaustive branches, unwind cleanup, bit-level validity of default value words, the downstream `entry+0x20` helper, later cancellation and matching, and the remaining book state are unresolved. No captured node execution or chain data was used.

Next question: what exact set transition does the downstream helper apply to `entry+0x20`, including duplicate slot keys and a full internal-node split, and how is that state removed during cancellation?
