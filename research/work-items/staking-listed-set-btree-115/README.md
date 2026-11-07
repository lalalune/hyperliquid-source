# staking: recover the node #115 listed signer sets as BTreeSet<[u8; 20]> - lazy builders, vacant insert with node splits, and the tree drop

This packet makes it possible to write the container behind the listed-signer sets of node #115 from bytes: a B-tree set of 20-byte addresses with 11 keys per node (leaf 0xe8 bytes, internal 0x148 bytes), the two lazy builders that fill it (five addresses and two addresses), the vacant insert that either stores a key in place or splits a full node around key 4, 5 or 6 and grows the root, and the drop that frees every node child-first. All six bodies run as real bytes in a Python interpreter, and a separately written B-tree rule list predicts every byte of every node they leave behind, in 11,365 cases with 0 mismatches.

- Component ID: staking (Staking and validator lifecycle); first task: signer admission and validator membership. The packet requests no gate.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6` / no reference source is used for any claim here.
- Claim status: observation for everything under Evidence (ELF bytes, run by the interpreter of this tool). Lines marked inference are not proved. Unresolved items are under limitations.
- Scope included (real bytes): builder A `0x14c4020`, builder B `0x14c4570`, vacant insert `0x156ea10` and its byte twin `0x156d9b0`, the split-capable insert `0x148aae0` that both reach, and the tree drop `0x1541a00`. Stubs with checked arguments: `memcpy`, `memmove`, `memcmp` (GOT `0x64df508`, `0x64df568`, `0x64dfb50`), the allocator behind slot `0x64df480`, the allocation error handler behind `0x64df490`, the sized free behind `0x64df4a0`, and five panic entries. Excluded: the callers of the two lazy statics (`0x64efcb0`, `0x64efc80`), the inline search loops of other callers such as the staking admission gate, `0x14cd400` and the row walks `0x1506e40`/`0x1507680` that also call the twin `0x156d9b0`.
- Overlap: `rg 0x148aae0 0x156ea10 0x1541a00 0x14c4570` over `research/work-items` finds these bodies only in RE-001 call-site lists (`callers.tsv`, `records.json`), never decoded. The open PR list has none of the addresses. The address `0x14c4020` appears only as a caller row.

## Reproduce

From the repository root:

```
python3 tools/staking_listed_set115.py --out research/work-items/staking-listed-set-btree-115
python3 -m unittest tests.test_staking_listed_set115
```

The tool takes about 35 s and 0.53 GB of memory (4 worker processes for the byte-edit controls). It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, checks the input SHA-256 first, starts no external program and never executes the binary. Cases are made one at a time, run, compared and dropped; only counts are kept. Generated files: `evidence.json`, `measure.json`, `path.tsv`, `stubs.tsv`, `function-rows.tsv`, `constants.tsv`, `layouts.tsv`, `listed-keys.tsv`, `lazy-rows.tsv`, `scenarios.tsv` (every 7th case), `mutations.tsv`, `controls.tsv`. `MANIFEST.sha256` covers them and this README. Two runs from a different working directory and hash seed give identical bytes.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs. Slot targets come from `.rela.dyn` RELATIVE rows; the three libc slots are GLOB_DAT rows (`memcpy`, `memmove`, `memcmp`).

### Map

```
static 0x64efcb0 -> builder A 0x14c4020  (5 addresses)  \  value words +0x18 = +0x20 = 1 after the build
static 0x64efc80 -> builder B 0x14c4570  (2 addresses)  /
  inline search per key (memcmp 20 bytes, node len at +0xe6, edge i at +0xe8+8*i)
    equal  -> key skipped
    vacant -> 0x156ea10  (entry: map, node, height, idx, key[20])
                empty tree: malloc(0xe8), parent 0, len 1
                else: 0x148aae0 insert_recursing, then length += 1
  on return: map (root, height, length) copied to the lazy value
0x156d9b0  same body as 0x156ea10 (6 rows differ, all displacements)
0x1541a00  drop: walks the set child-first, sized free of every node
```

### Node layout

| Field | Offset | Rule |
|---|---|---|
| parent | `+0x00` | pointer; 0 for the root; written for a new node only |
| keys | `+0x08` | 11 keys of 20 bytes |
| parent index | `+0xe4` | u16, written when the node is attached to a parent |
| length | `+0xe6` | u16, at most 11 |
| edges | `+0xe8` | 12 pointers; present in a 0x148 byte internal node only |

`layouts.tsv` lists these. A new node is filled with whatever the allocator returns; the tool's allocator fills 0xa5, so the stale bytes after a split are predicted too (the left node keeps its moved keys).

### Split rule

A full node (11 keys) is split by the insertion index `i` of the new key. `0x148aae0` chooses the median and the side exactly as follows (all 12 indices are cases, see `scenarios.tsv`).

| `i` | median index | key goes to |
|---|---|---|
| 0..4 | 4 | left node at `i` |
| 5 | 5 | left node at 5 |
| 6 | 5 | right node at 0 |
| 7..11 | 6 | right node at `i - 7` |

The right node is allocated first (0xe8 or 0x148 bytes), then the parent is asked to take the median; a full parent splits the same way, and a root with no parent gets a new 0x148 byte root with the old root at edge 0 and the new node at edge 1 (`map.height` + 1). So a root split at height 1 makes three allocations in the order leaf, internal, internal. The insert returns the node and index where the key landed (that can be the new right node), and the wrapper adds 1 to the map length afterwards.

### Builders

`listed-keys.tsv` has the keys. Builder A inserts first the key held in immediates (`2572e758...1397`), then four keys in order, each searched against a rodata copy (`0x464932`, `0x464946`, `0x46495a`, `0x46496e`) and inserted from immediates; all four rodata copies equal the inserted bytes (column `equal`). Builder B inserts `5fd03b40...a052`, then searches `0x46491e` and inserts it. An equal key is skipped (the set keeps one copy). The result record is `root, height, length, 1, 1`. Which chain each static belongs to is not read here.

### Drop

`0x1541a00` takes the set (root, height, length). It frees nodes in post-order with `free(ptr, 0xe8 or 0x148, 0)`. The length word only selects the walk: one word too small still frees every node (cases `drop` with `delta=-1`), one too large ends in a panic entry (5 range controls with +1 and 5 with +2 on trees of 1, 5, 12, 40 and 150 keys).

## Implementation and comparison

`tools/staking_listed_set115.py` contains the interpreter (an x86-64 subset decoder and machine reading the bytes), the fixture that writes a model tree into memory byte for byte, and the rule list (`MTree`: search, shift-insert, split points, child link fixes, root growth, allocation order, post-order frees). Each case builds the model tree, writes it, runs the real bytes and compares the whole node memory (parent, parent index, length, 11 key slots, 12 edge slots) with the model after the insert, plus the returned handle, the malloc sizes in order, and for failures the `(align, size)` passed to the allocation error handler.

Case groups (`evidence.json`):

| Group | Cases | What it checks |
|---|---|---|
| `insert`, `insert_twin` | 2,344 each | every gap of trees of 0..200 keys grown ascending, descending, shuffled and outside-in; 0..3 splits per insert |
| `grow` | 1,200 | 150 inserts in four orders, both vacant bodies alternating, every step compared |
| `fault` | 177 | the k-th malloc of an insert fails |
| `drop` | 386 | free log of 30 shapes x 9 builds, plus 116 with a length word one short |
| `builder_a`, `builder_b` | 4,802, 98 | other key bytes patched into the immediates and the rodata copies (7-key alphabet, memcmp returning a sign or a byte difference) |
| `builder_fault`, `builder_real` | 12, 2 | allocation failures in the builders; the unpatched binary |

## Results and limitations

11,365 cases, 0 mismatches. 291 negative controls, all detected: 5 moved layout fields, 13 wrong rule lists (reversed order, 16-byte compare, no child link fix, median one low, median kept in the left node, height not raised, length not counted, wrong internal size, pre-order free, internal nodes skipped, internal freed as leaf, no dedupe, last key dropped), 258 byte edits killed, 15 out-of-range inputs (wrong digest, non-FDE address, address outside every FDE or section, 10 drop length words, a leaf of 12 keys). 1,087 instructions of the six bodies are reached. Byte edits: 291 possible, 258 killed, 33 survived (15 in `0x148aae0`, 12 in the two builders, 4 in the drop, 1 in each vacant body). By kind the survivors are 16 compare immediates, 13 move immediates, 2 add immediates, 1 cmov and 1 conditional jump. The survivors were not classified one by one and no cause is claimed for them; each is listed with address and kind in `mutations.tsv`. One survivor group is explained by a test: the handle height word of the vacant entry is ignored (heights 0, 5 and 0xffff give identical memory).

- The inline search of the builders is the only search that runs as bytes. The cases that start from a populated tree locate the vacant slot with the rule list, so the search of other callers is not claimed.
- Which chain or role uses each lazy static, and whether the admission gate reads them, is not established here (inference only: the listed-signer test of the gate is a search of a set of 20-byte keys).
- The allocator, `memcpy`, `memmove`, `memcmp` and the free routine are contract stubs; real `memcmp` may return any int with the right sign (cases with a byte difference pass).
- Trees of more than 200 keys are not run; a third split level (a root at height 3 needs more than 1,727 keys) is not reached by any case.
- The twin `0x156d9b0` is claimed equal to `0x156ea10` by 67 aligned rows, 6 of which differ in displacement fields only, and by running both on the same cases.
- The tool never writes the lazy value state words beyond what the builders write; their reader is not in scope.

Next question: which function reads the two lazy statics (`0x64efcb0`, `0x64efc80`) and compares a signer against them, so the role of each set can be named.
