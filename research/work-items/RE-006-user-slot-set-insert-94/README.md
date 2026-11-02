# RE-006: user-slot set insertion and split propagation on node 94

This packet establishes how the user's resting-slot index set inserts a key and propagates 11-key splits through parent nodes, including the distinct positions 5 and 6, so the book reconstruction can preserve the target's node layout and split decisions.

- Component ID: `orderbook`, task RE-006 (book insertion).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a search lead only; no code was copied.
- Claim status: selected instruction bytes, FDE records, branch destinations, relocation records and bounded call sites are observations. Container roles and the synthetic state projections are inferences. Execution and reachability remain unresolved.
- Scope included and excluded: two selected, previously unrecorded FDEs: a set-insert counterpart and its split/propagate helper. Previously studied book callers and their set writer are comparison context only, not selected functions. Slot allocation, other book indexes, matching, cancellation, allocation internals, and complete error or rollback behavior are outside this packet.

## Reproduce

From the repository root with Python 3.12.3 on Linux x86-64 and the captured node at its artifact location:

```sh
python3 tools/artifacts.py verify
PYTHONHASHSEED=0 TZ=UTC python3 tools/book_user_slot_set94.py --out work/re006-slot-set-check/a
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/book_user_slot_set94.py --out work/re006-slot-set-check/b
diff -r work/re006-slot-set-check/a work/re006-slot-set-check/b
diff -r --exclude=README.md --exclude=MANIFEST.sha256 work/re006-slot-set-check/a research/work-items/RE-006-user-slot-set-insert-94
python3 -m unittest tests.test_book_user_slot_set94
python3 tools/catalogue.py --check
```

The collector authenticates the complete file before analysis, imports `tools/elf_index.py` and `tools/fde_extents.py`, excludes `SHT_NOBITS` from address mapping, and reads ELF records and fixed instruction patterns with Python's standard library. Neither the collector nor its tests call a disassembler, run the target, or use network access. GNU objdump 2.42 was used only for manual instruction inspection. The tests and the two regenerations also pass with a Python-only command path. `MANIFEST.sha256` hashes this README and every generated file in this directory; the input digest is above.

## Evidence

Addresses are linked ELF virtual addresses, ranges are half-open, and file offsets in the tables are zero-based. In these executable ranges the file offset is VA minus `0x1000`; the generator computes it from section headers. An FDE is an unwind-described extent, not an independent proof of a source-level boundary or of a complete function census.

| Selected role | FDE range | Bytes | Raw SHA-256 |
| --- | --- | ---: | --- |
| Insertion counterpart | `0x285db90..0x285dcef` | 351 | `bfaed318d6069719518fbe6c22f0ad464d21b636abba178b1197aa95dfa0740b` |
| Node insert and split propagation | `0x1a788b0..0x1a79067` | 1975 | `a6054488ae596cec2d31f2072101612e9e7dbe7ee9389af49f3af9afef41c9df` |

`functions.tsv` contains the full selected bodies, FDE/CIE/LSDA coordinates and hashes; `witnesses.tsv` contains the pinned windows, and `constants.tsv` decodes selected immediate and displacement fields. `branches.tsv` records 45 selected conditional sites; it is not an exhaustive CFG. `calls.tsv`, `failure-edges.tsv`, `relocations.tsv` and `diagnostics.tsv` retain checked destinations, the 14 selected failure edges, eight external slots and five diagnostic records. All numbers and raw bytes in these files are extracted from the authenticated ELF. The path of an embedded diagnostic is reduced to its source suffix before output.

### Connection to the book

Two already studied resting-order contexts supply the link to the new helper:

```text
slot writer call 0x26ea59a -> 0x232c410; return saved on stack
  user-entry call 0x26ea6ae -> 0x25a7a40; returned pointer + 0x20
    set call 0x26ea6c2 -> 0x285cc70
      split call 0x285cd9a -> 0x1a788b0

slot writer call 0x26edf1d -> 0x232c560; return saved in r15
  user-entry call 0x26ee02f -> 0x25a7730; returned pointer + 0x20
    set call 0x26ee040 -> 0x285cc70
      split call 0x285cd9a -> 0x1a788b0
```

The first caller later loads the saved stack word as the set key; this link assumes intervening calls do not write through an alias to that stack location. The second keeps the value in the callee-saved register `r15` under the usual x86-64 ABI. The preceding slot writer's exact contract is supplied by the existing `RE-006-price-level-lifecycle-94` and `RE-006-spot-order-insert-94` research, not independently re-established here. Both caller windows are retained for review. The earlier `RE-006-user-book-cancel-94` packet identifies the user entry's `+0x20` field as a set of slab indexes. This packet does not analyze the previously documented caller FDEs or the prior set writer as selected bodies.

The selected counterpart calls the same split at `0x285dcba`. Its 351-byte body and the 351-byte context window at `0x285cc70` have 12 differing bytes. All differences lie in six explicitly listed four-byte PC-relative operands. After masking only those operands, the bytes hash to `9d3232c4a17fa8a34b93cd73f54a16c3ff710b7da5d2636edba230434c5a5d08`; each operand independently resolves to the same target in both copies. `wrapper-bodies.tsv` retains both unmasked windows, and `wrapper-comparison.tsv` records both raw instructions, masks and resolved destinations. Thus the counterpart's selected insertion logic applies to the context window under exactly that comparison; it is not a whole-binary comparison or a claim that other monomorphs are equal.

### Search and insertion

The selected insertion counterpart takes a tree-header pointer in `rdi` and a u64 key in `rsi`. It reads the root and height at header `+0x00/+0x08`, and the count at `+0x10`. At each node, it reads a u16 live-key count at `+0x62`, compares u64 keys at `+0x08` with stride 8 in unsigned ascending order, and uses child pointers at `+0x68` with stride 8 when descending. Equal keys return with `AL = 1` without calling the insertion helper or incrementing the count. On an absent key it inserts and returns zero. The two book call sites do not inspect this return before subsequently overwriting `eax`.

For a null root, the counterpart requests `0x68` bytes, writes a null parent and zero count, sets the root and height, then writes the first key. For an existing root, it constructs a cursor and calls the split helper. Each successful new key increments header `+0x10` after insertion with a qword `inc`; mechanically this instruction wraps on u64 overflow. Whether a valid book can reach such a count is not established. Allocation failure and the initial capacity assertion have separate branches in `failure-edges.tsv`.

### Node layout and propagation

| Offset or size | Observed use |
| --- | --- |
| Node `+0x00` | Parent pointer; null at root. |
| Node `+0x08` | u64 keys, stride 8. |
| Node `+0x60`, `+0x62` | u16 parent-edge index and live-key count. |
| Internal node `+0x68` | Child pointers, stride 8. |
| `0x68`, `0xc8` | Requested bytes for a leaf and internal node respectively. |
| Capacity `11` | A live count below 11 takes nonfull insertion; 11 takes a split. |

The reference lead in `l1/book/book/mod.rs` models a per-user order-ID-to-slot mapping. The selected `+0x20` member here instead uses a key-only tree on the observed path; this does not exclude an order-ID mapping elsewhere. The earlier user-cancellation packet already identified that distinction; the new evidence here is its insertion and split mechanics.

The key and edge offsets leave room for eleven keys and twelve child pointers. Those storage roles and the label B-tree are inferred from the comparisons, split, propagation and parent/edge writes, not recovered Rust type declarations. The helper returns a three-word cursor. A nonfull leaf shifts the suffix only when the insertion index is below the old length; `nonfull-cases.tsv` projects all 66 valid `(length, index)` pairs for lengths 0 through 10. These are synthetic examples, not target executions, and say nothing about malformed indices.

For a valid full node with 11 old keys, the pinned leaf comparisons choose the following pivot and destination. The corresponding full-parent tests use the same 5/6 boundaries. `split-cases.tsv` enumerates all twelve valid positions; `parent-cases.tsv` shows the corresponding synthetic child-edge distribution.

| Insertion index | Promoted old-key index | Destination for new key | Left keys after insert | Right keys after insert |
| --- | ---: | --- | ---: | ---: |
| 0–4 | 4 | left, same index | 5 | 6 |
| 5 | 5 | left, index 5 | 6 | 5 |
| 6 | 5 | right, index 0 | 5 | 6 |
| 7–11 | 6 | right, index minus 7 | 6 | 5 |

For a split, the upper keys are copied to the sibling and both counts are written. An internal split also copies its child pointers and rewrites each moved child's parent and parent-edge index. A nonfull parent shifts its key and edge suffixes and repairs affected child links. A full parent splits again and the loop ascends. If no parent remains, the helper requests a `0xc8`-byte root, installs the former root as child zero, increments the tree height, and inserts the promoted key and new sibling as the next edge. These are observations from the pinned blocks, qualified by valid-tree and successful-allocation assumptions.

### Failure observations

The table of failure edges separates initial allocation, leaf and internal sibling allocation, copy/edge bounds, parent-height mismatch, unequal child-slice lengths, missing old root, root allocation, height overflow, root-height mismatch and root-capacity assertion. The five retained diagnostic records tie selected assertion strings to relocated `src/collections/btree/node.rs` locations. `memcpy` and `memmove` are identified by dynamic-symbol relocations; the remaining external-slot roles are inferred from call arguments and control flow. The behavior of those callees and cleanup after a failure is not established.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No compiled Rust, target execution, byte-equivalence measurement, or behavior comparison is claimed. The only normalization is the six four-byte wrapper operands listed above; their resolved targets are compared before masking. Other calls, indirect data, relocation closure, vtables and whole-ELF equivalence remain unmeasured.

The split and edge tables are deterministic projections of the pinned comparisons for valid synthetic nodes. They do not execute or emulate node code. Negative controls corrupt the input digest, unwind start and FDE extent, each of 28 byte witnesses, each of 45 selected conditional opcodes, the direct-call opcode, each masked operand of the counterpart, an unmasked byte, and out-of-range and NOBITS addresses. They also reject invalid inputs to the synthetic projection; that rejection is a model boundary, not a target failure claim.

## Results and limitations

Thirteen focused unittest methods passed with no skips. The collector produced 14 files, including 12 full-leaf positions, 12 parent-edge examples and 66 nonfull cases; independent regeneration under two hash seeds and time zones was byte-identical. `artifacts.py verify` and `catalogue.py --check` passed. No component progress gate is requested.

The selected counterpart has callers outside the book, so the comparison does not prove book-exclusive ownership. The caller-to-slot-key relationship depends on the cited earlier packet and the alias/ABI qualifications above. The behavior of allocator, copy, panic and unwind callees, complete malformed-state behavior, the full order admission path, other indexes, matching and cancellation are unresolved. No claim is made that every conditional instruction or every user insertion has been found.

Next question: trace how cancellation removes the same `+0x20` slab-index set entry and repairs that set's nodes, using function ranges not already covered by the user-index and untriggered-order deletion packets.
