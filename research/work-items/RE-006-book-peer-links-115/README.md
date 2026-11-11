# RE-006: node #115 book order peer link and parent detach, rebuilt from the bytes and proven on 10,400 cases

This packet lets a Rust port of the node #115 order book write the two order-relation updates of `l1/book` as exact functions: the mutual peer link of two orders and the parent detach of one order, including how an order record is found (order-id map into the slab, or user store then order store), what each failure path leaves untouched, which writes happen before the bounds panic, and how the parent's child list is compacted in place. Four bodies (`0x58e4300`, `0x58e48e0`, `0x58e4ec0`, `0x58e5510`) are run as real instructions in a Python x86-64 evaluator and compared with an independently written specification of the book layout on 10,400 generated books; 434 of 434 deliberately wrong variants are rejected (0 proven equivalent, 0 unexplained).

- Component ID: orderbook (work item RE-006)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: workspace commit of origin/main at the time of the run; no reference source is copied, every offset below is read from the bytes
- Claim status: observation for every table row the evaluator ran against the bytes; inference only where a section says so
- Scope included: the four bodies below from the first byte to the exact FDE end, as real code
- Scope excluded (stubbed with arguments checked): the order-id hash probe `0x4ef4010`, the sorted-ring searches `0x57f7bd0` (users) and `0x57fbf50` (orders), the 20-byte compare reached through the GOT slot `0x64dfb50`, and the bounds-panic slot `0x64df620`. The callers of the four bodies are not analysed here.
- Related work: `RE-006-node115-book-order-unlink`, `RE-006-node115-shared-insert-return` and `RE-006-node115-book-ring-append` pin other bodies of the same book; none of their addresses is used here.

## Reproduce

Python 3 standard library plus the shared `tools/elf_index.py` and `tools/fde_extents.py`; no external program runs, the binary is never executed, nothing touches a network. The tool refuses any other digest. One run takes about two minutes and peaks near 470 MB; the unit file takes about 12 seconds.

```
python3 tools/book_peer_links_115.py --out research/work-items/RE-006-book-peer-links-115
python3 -m unittest tests.test_book_peer_links_115
```

Defaults: 2,600 generated books per body (10,400 in all). `MANIFEST.sha256` lists every file here except itself.

## Evidence

Coordinates are ELF virtual addresses in `.text`; bounds are FDE bounds from the shared parser (`scope.tsv`, SHA-256 of each body included).

| Entry | FDE end | Bytes | Operation | SHA-256 of the body |
| --- | --- | ---: | --- | --- |
| `0x58e4300` | `0x58e48d9` | 1497 | link | `81e30f4ec4fbcc8ecf91f0e6326ea42f7d8f64e1e1a783398f51f8a2287c9f00` |
| `0x58e48e0` | `0x58e4eb9` | 1497 | link | `3ef08c745454f89ed5af425a17b146bc03a49159a14b33cf1706b26daace2385` |
| `0x58e4ec0` | `0x58e5504` | 1604 | detach | `89276b20504e921f8689cb4efd91b7f78f45949a95968aa909323af92e470114` |
| `0x58e5510` | `0x58e5b54` | 1604 | detach | `7bc72dbd595005866c2dca5f4a994f0c5584e44644a8ca0a4ef67e51e38c7dc9` |

### Observations: shape of the bodies

- The two link bodies are identical instruction for instruction; the two detach bodies likewise. They differ only in the rip-relative displacements to the same GOT slots and panic location (`copies.tsv`: 0 differing decoded rows, a few differing raw bytes).
- Arguments: `rdi` book, `rsi` pointer to a 20-byte user key, `rdx` first order id, and for the link bodies `rcx` second order id. The key is copied to the stack (16 bytes plus one dword) and compared with `pcmpeqb`/`pand`/`pmovmskb` against 0xffff, i.e. 20 bytes.
- Finding an order record (identical code in all four bodies, run once per id):
  1. call the order-id probe `0x4ef4010` with the book and the id. When it answers 1 with an index, that index is checked against the length at book `+0x10` (a bounds panic through the slot at `0x64df620` with the location at `0x649e918` when it is not below), the 24-byte record at book `+0x8` gives a slab index at record `+0x10`, that must be below book `+0x90`; the 0x110-byte slab slot at book `+0x88` must not have the dword tag 2 at `+0` and must hold the 20 key bytes at slot `+0xf8`. The record body is slot `+0x20`.
  2. otherwise the user store: when the qword at book `+0xe8` is `0x8000000000000000` it is a B-tree (root `+0xf0`, height `+0xf8`, node length word `+0x4ae`, 20-byte keys from `+0x3d0`, 0x58-byte values from `+0x8`, edges from `+0x4b0`) walked with the 20-byte compare; otherwise it is a sorted ring (capacity `+0xe8`, pointer `+0xf0`, head `+0xf8`, length `+0x100`) searched by `0x57f7bd0` whose position is checked below the length and mapped through the head with one conditional subtract of the capacity; user records are 0x70 apart and the user body is entry `+0x18`.
  3. the same split decides the order store inside a user body: qword `+0x20` equal to `0x8000000000000000` means a B-tree (root `+0x28`, height `+0x30`, length word `+0x9aa`, u64 keys from `+0x8`, 0xd8-byte values from `+0x60`, edges from `+0x9b0`) otherwise a ring (capacity `+0x20`, pointer `+0x28`, head `+0x30`, length `+0x38`, entries 0xe0 apart, record at entry `+0x8`) searched by `0x57fbf50`.
  4. a record reached through either store has its first dword compared with 2; when equal the body address moves 8 bytes on. A record reached through the slab does not get this step.
- Link bodies: find the first order and, if present, store qword 1 at body `+0x20` and the second id at `+0x28`; then find the second order (the failure of the first does not stop the second) and store 1 and the first id the same way. Detach bodies: find the order, store qword 0 at body `+0x10` (this happens even when the old tag was not 1), return unless the old dword was 1; find the order whose id was stored at body `+0x18` of the first, return when its list length at `+0x40` is 0 or the id is not in the u64 list at `+0x38`; otherwise drop every occurrence of the id by in-place compaction and store the new length at `+0x40` (entries from the new length on keep their old values).
- Every bounds failure of the id map index is a panic: writes done before it stay (a link whose second id panics has already written the first order).

### Inferences (not proven by the bytes)

- The names peer (`+0x20`/`+0x28`) and parent (`+0x10`/`+0x18`) with a child id list (`+0x38`/`+0x40`) follow from the shapes: the link is symmetric, the detach takes an option and edits a list of ids in the option's target. A caller-side proof is not part of this packet.
- The stubbed searches are modelled as `Result<usize, usize>`: found gives position, absent gives the insertion point in `rdx`; only the found position is used by the bodies (a mutant that ignores the not-found bit is detected only because the stub supplies an in-range insertion point).

## Implementation and comparison

`tools/book_peer_links_115.py` holds (1) a small x86-64 evaluator (decoder, flags, the SSE integer forms these bodies need), (2) a layout writer that places generated books into the evaluator heap (users as ring or B-tree of height 0 to 2, orders as ring or B-tree, a slab, an id map index, kids lists with duplicates, vacant niche tags, junk bytes everywhere else) and (3) a specification `Spec` written from the table above that predicts the ordered stub calls (probe, ring searches, every 20-byte compare), the panic, and every byte stored. A case passes when calls, panic and the complete used heap match. No Rust is implemented in this packet ("not yet implemented"); the specification is Python.

Controls: 420 byte mutants of the bodies (192 inverted conditional jumps, 228 flipped low immediate bytes) each run on up to 300 generated books per body until one disagrees, 6 wrong specifications (equal peer ids, no second link, parent kept, only the first occurrence removed, reversed compare, no panic) and 8 boundary and corruption controls (a flipped binary byte, entries off the FDE grid, FDE ends).

## Results and limitations

- Cases: 10,400 (803 end in the bounds panic, the rest return normally; see `outcomes.tsv` for the 48 classes by operation, user store, order store and number of stores).
- Negative controls: 434, detected 434, equivalent 0, unexplained 0 (`measure.json`, `mutants.tsv`, `controls.tsv`, `equivalent-mutants.tsv`).
- `sites.tsv` lists every layout displacement and immediate the bodies use (stride 0x110, 0xd8, 0xe0, 0x70, the tag 2, the niche word, the key and length offsets).
- Limits: the lookups below the bodies are stubs; B-trees above height 2 and nodes with more than 11 keys are not generated; no caller is shown; the order-id probe is assumed to answer index 1 only through its documented register contract (rax = 1, rdx = index), which is inferred from the two instructions that read it; the field names are inferences. No progress gate is requested.
- Next question: the callers of these four bodies (which operation arms reach link and detach, and what the id map holds when they run) and the three searches `0x4ef4010`, `0x57f7bd0`, `0x57fbf50` as real code.
