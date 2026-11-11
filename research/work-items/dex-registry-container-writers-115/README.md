# dex-registry: msgpack container writers (map loop, sequence loop, array header, finish) in node #115

This packet makes the container writers below the Hip3 `schema` record reconstructible as pure functions: the `asset_to_oi_cap` map writer, the `sub_deployers` sequence writer, the msgpack array-header writer they share, the buffered-writer finish, and the two B-tree iterator `next` bodies. Earlier packets stubbed all of these as "map" and "seq" roles. Here 33 original bodies (three copy families, 3,244 instructions) run from their original bytes in 11,730 cases with 0 mismatches against an independent reconstruction, and all 37 negative controls (12 wrong reconstructions, 21 byte corruptions of the capture, 4 out-of-range inputs) are detected.

- Component ID: `dex-registry` (DEX metadata and clearinghouse registry; first task: recover identifiers, lookup rules and deployment ownership checks).
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No #94 material and no reference source were used.
- Claim status:
  - Observation: bytes, call targets, relocated slot targets, FDE extents and the interpreted behaviour of the listed bodies.
  - Inference: the msgpack reading (fixarray/array16/array32 markers, array-of-two entries), the container and iterator names, and the stage names `key`, `val`, `end`, `elem` (taken from call order).
  - Unresolved: the internals of the four stage writers and of the allocator, copy and panic slots.
- Scope:
  - Included (three copy families, copy 1 / 2 / 3):

    | Body | Copy 1 | Copy 2 | Copy 3 |
    |---|---|---|---|
    | map loop | `0x2202220` | `0x4151980` | `0x52c5a70` |
    | sequence loop | `0x2205280` | `0x4177540` | `0x52b19d0` |
    | sequence wrapper (container to iterator) | `0x2d562f0` | `0x3c6f250` | `0x4da9790` |
    | array header | `0x25e7c10` | `0x3d50540` | `0x57cee80` |
    | finish | `0x227e1b0` | `0x41acd70` | `0x5306d60` |
    | map entry writer | `0x22877f0` | `0x41bf660` | `0x5315e20` |
    | map iterator next | `0x2388170` | `0x37c3750` | `0x51347f0` |
    | sequence iterator next | `0x23896a0` | `0x37cd990` | `0x5134a00` |
    | marker normaliser | `0x25eab50` | `0x3d52310` | `0x57d0b20` |
    | vec reserve | `0x231e050` | `0x43bd910` | `0x5963a10` |
    | grow helper | `0x231dc90` | `0x43bd550` | `0x5963650` |

  - Excluded: the stage writers (`stage-roles.tsv`), the nine allocator/copy/panic GOT slots (`slots.tsv`), unwinding landing pads, the deserializer side, and any progress gate.

## Reproduce

From the repository root, with Python 3 standard library only (binutils are not needed on PATH):

```sh
python3 tools/dex_registry_container_writers_115.py --out research/work-items/dex-registry-container-writers-115
python3 -m unittest tests.test_dex_registry_container_writers_115
```

How the tool works:
- It checks the capture SHA-256 first and refuses any other input.
- It reads sections through `tools/elf_index.py` (NOBITS excluded), function extents through `tools/fde_extents.py` and `R_X86_64_RELATIVE` addends from `.rela.dyn`; it imports the image reader of `tools/hip3_subrecord_helpers_115.py`.
- It decodes every body with a fixed-pattern x86-64 decoder; each body must land exactly on its FDE end. It then runs the original bytes in an interpreter with ZF/CF/SF/OF. The capture is never executed and no external program is called.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical output (checked with `diff -r`). One run takes about 60 s and 260 MB.
- The tool writes `measure.json` with `cases`, `negative_controls` and `negative_detected`.

## Evidence

Coordinates are linked virtual addresses; extents are FDE `[start, end)` values.

Observed behaviour (interpreted from bytes, equal in the three copies unless stated):

| Body | Observed behaviour |
|---|---|
| iterator words | Nine words. Word 0 == 2: two slices `[w1,w2)` and `[w3,w4)`, 16-byte (map) or 32-byte (sequence) elements, length is the sum of both. Otherwise a lazy B-tree front (root `w2`, height `w3`) and the length is word 8. |
| array header | `n < 16`: one byte `0x90 | n`; `n < 0x10000`: `0xdc` and a big-endian u16; otherwise `0xdd` and a big-endian u32. The marker goes through the normaliser (`0x90` keeps the low four bits, `0xc0..0xdf` pass). A byte write reserves when the buffer is full; a 2- or 4-byte write reserves when fewer bytes remain. |
| map and sequence loop | `n >> 32 == 0`: write the header with `n`, then every item straight into the caller's writer. Otherwise: allocate a 0x80-byte buffer, copy the writer's config (u16 at +0x18, u16 at +0x1a masked with `0x0101`, byte at +0x1c) into a buffer writer, count items in a u32 (panic at `0xffffffff`), and let finish write the header with the count. The first non-OK result word is returned; a buffered run frees its buffer on error. |
| map entry | Push `0x92` unless the writer byte at +0x1c is 2, then call the three stage writers with a five-word state `(0 or 2^63, 1, 0, writer, 2)`; the first non-OK result is copied out. |
| finish | Capacity word `2^63` (streaming): return OK. Otherwise write the header with the count, reserve and copy the buffered bytes, free the buffer. |
| iterators | Map next: keys at +8 (stride 8), values at +0x60 (stride 8), parent index u16 at +0xb8, length u16 at +0xba, edges at +0xc0. Sequence next: values at +8 (stride 24), keys at +0x114 (stride 1), parent index at +0x110, length at +0x112, edges at +0x120. Exhaustion with items still counted ends in a panic-location slot call. |
| wrapper | Container words `(cap, ptr, head, len)`: `cap == 2^63` is a B-tree `(root, height, len)`; otherwise a ring buffer split into two slices (head wraps by `cap`, empty gives equal pointers). |
| reserve | `max(2*cap, len+add, 8)`, through the grow helper with the alloc or realloc slot. |

Raw per-instruction rows are in `instructions.tsv`; `functions.tsv` has the byte hash of every body, `btree-layout.tsv` the node offsets (each read offset is checked to appear as a displacement of the iterator bodies), `stage-roles.tsv` the stage callees per copy (copy 3 calls its second stage writer first: `0x53206b0`), and `slots.tsv` the relocated slots.

## Implementation and comparison

The reconstruction (`m_header`, `m_entry`, `m_elem`, `m_loop`, `m_wrapper`, `m_finish_tail`) is plain Python over lists and byte strings. It does not read the capture. Each case builds memory (writer, iterator, B-tree nodes laid out with the observed offsets, ring slices), runs the original body, and compares output bytes, capacity, result words, panic kind and the ordered call log (stage calls with their state words, writer config, item identity; allocator, copy and dealloc calls). Stage writers and slots are stubs that record their arguments and return OK or a planned error.

| Family | Cases |
|---|---|
| map loop (3 copies) | 5,250 |
| sequence loop (3 copies) | 3,450 |
| array header | 990 |
| finish | 480 |
| sequence wrapper into the real loop | 1,560 |

Total 11,730 cases, 7,149,997 interpreted steps, 0 mismatches (`summary.json`, `all_cases_sha256` over every case outcome). Inputs vary slices (0 to 18 and 0 to 17 items, empty first or second slice), B-tree height 0 to 2, node lengths 1 to 4, writer capacity (0 to 64) and length (0 to 6), writer flags, planned stage errors, planned allocation failures and length words that force the buffered branch.

Negative controls (`controls.tsv`, all 37 detected, subset of 1,971 family-spanning cases each):
- 12 wrong reconstructions (header limit, endianness, marker, flag skip, reserve rules, buffered limit, error and finish deallocation, count, empty copy, tree order);
- 21 corrupted bytes of the capture (header limits and marker immediates, slice shifts and strides, config mask, buffer size, finish OK word, entry marker and flag, reserve minimum, next-iterator offsets, wrapper scale, grow helper); some are caught as refusals of the interpreter (step limit, unset read, store outside scratch), which counts as detection;
- 4 out-of-range inputs (wrong digest, address outside sections, short unwind extent, call to an unmodelled target).

## Results and limitations

Metrics: 11,730 cases, 0 mismatches; 37 of 37 negative controls detected; 33 bodies, 3,244 instructions, 2,679 executed; 531 non-nop instructions never executed (`unexecuted.tsv`); 14 unit tests.

Limits:
- The unexecuted rows (unwind landing pads, the `0xffffffff` count overflow, the header error branch, the iterator-tag panic, aligned-allocation branches) are listed but not classified row by row.
- A buffered run can only end through an error or an iterator panic here, because it needs a length word of at least 2^32 items; the buffered finish is therefore proven by the direct finish cases.
- The stage names come from call order; their meaning (key, value, end of entry, sequence element) is inference.
- Slot targets are not interpreted; only their roles in these bodies are observed.
- No progress gate is requested.

Next question: the four stage writers per copy (`0x2296160`, `0x2296fa0`, `0x22999e0`, `0x22927f0` and their copies), which call the u64/str writers of the earlier packets.
