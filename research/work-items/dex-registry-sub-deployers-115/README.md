# dex-registry: Hip3 sub_deployers element writer (action name, address array, hex text) in node #115

This packet makes the element of the Hip3 `sub_deployers` list reconstructible as a pure function: each element is the pair `[action, [address, ...]]`, where the action is one of 23 deploy actions (15 plain names for tags 8..22 and eight `hip3Star` actions for tags 0..7, written as the one-entry map `{"hip3Star": name}`) and every address of the B-tree set is written as a 42-character `0x` + lowercase-hex msgpack string. The earlier container packet left this element writer as a stub; here 46 original bodies (three copy families, 7286 instructions, with the str/uint/array-header/tuple-end/finish/reserve writers and the shared hex formatter running as real dependencies) run from their original bytes in 12036 cases with 0 mismatches against an independent reconstruction, and all 45 negative controls (14 wrong reconstructions, byte corruptions of the capture, and out-of-range inputs) are detected.

- Component ID: `dex-registry` (DEX metadata and clearinghouse registry; first task: recover identifiers, lookup rules and deployment ownership checks).
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No #94 material and no reference source were used.
- Claim status:
  - Observation: bytes, call targets, jump tables, relocated slot targets, FDE extents and the interpreted behaviour of the listed bodies, including the 23-entry action name table (`name-table.tsv`).
  - Inference: the names `sub_deployers`, "deploy action" and "address set" for the roles; the reading of the written bytes as msgpack (`0x92` array of two, `0x81` map, `0xa0..` fixstr, `0xd9` str8, `0x90..` fixarray).
  - Unresolved: the Rust type names of the action enum, which enum variants carry which payload beyond the tag byte, and the error-result branches (see Limits).
- Scope:
  - Included (three copy families, copy 1 / 2 / 3):

    | Body | Copy 1 | Copy 2 | Copy 3 |
    |---|---|---|---|
    | element writer | `0x22927f0` | `0x41c2c30` | `0x5312380` |
    | action name writer (jump table 1) | `0x2bc7610` | `0x44a3da0` | `0x54a20a0` |
    | `hip3Star` action name writer (jump table 2) | `0x2bc6150` | `0x44a2980` | `0x54a0ae0` |
    | address array writer | `0x2299050` | `0x41d3d00` | `0x53207f0` |
    | address array loop | `0x2228ba0` | `0x4152580` | `0x52808c0` |
    | B-tree set iterator next | `0x2387b20` | `0x37c5980` | `0x5138730` |

    The hex formatter `0x2eabb50` (behind GOT slot `0x64e4d08`) is shared and runs real. The str writers (`0x25e8bf0`, `0x41c6610`, `0x57cf5d0`), uint writers (`0x25e9f10`, `0x3d51450`, `0x57cfd20`), tuple ends (`0x22999e0`, `0x41d4150`, `0x5325140` with helpers `0x25e80c0`, `0x41c5b90`, `0x57cf350`), buffered finish, array header, marker, reserve and grow bodies are reconstructed by earlier packets; they run real here as dependencies only.
  - Excluded: the allocator, copy and panic slots (stubs recording their arguments), unwinding landing pads, the deserializer side, the containing record writers, and any progress gate.

## Reproduce

From the repository root, with Python 3 standard library only (binutils are not needed on PATH):

```sh
python3 tools/dex_registry_sub_deployers_115.py --out research/work-items/dex-registry-sub-deployers-115
python3 -m unittest tests.test_dex_registry_sub_deployers_115
```

How the tool works:
- It checks the capture SHA-256 first and refuses any other input.
- It reads sections through `tools/elf_index.py` (NOBITS excluded), function extents through `tools/fde_extents.py` and `R_X86_64_RELATIVE` addends from `.rela.dyn` (the hex slot must point at the hex formatter); it imports the image reader of `tools/hip3_subrecord_helpers_115.py`.
- It checks every role address against the call order inside the original bodies, decodes every body with a fixed-pattern x86-64 decoder (each body must land exactly on its FDE end), and then runs the original bytes in an interpreter with ZF/CF/SF/OF. The capture is never executed and no external program is called.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical output (checked with `diff -r`).
- The tool writes `measure.json` with `cases`, `negative_controls` and `negative_detected`.

## Evidence

Coordinates are linked virtual addresses; extents are FDE `[start, end)` values.

Observed behaviour (interpreted from bytes, equal in the three copies):

| Body | Observed behaviour |
|---|---|
| element writer | Writes the marker `0x92` (array of two; with writer byte +0x1c == 2 through the array-header writer, same bytes), calls the action name writer, then the address array writer with a tuple state `(2^63, 1, 0, writer, 2)`, then the tuple end. The result word is `2^63 + 4` on success. |
| action name writer | `index = tag - 8` if `tag >= 8` else 15; a 16-entry jump table of 32-bit offsets (`jump-tables.tsv`). Entries 0..14 write a name inline (fixstr marker `0xa0 | len`, or `0xd9 len`), entry 15 writes `0x81`, the key `hip3Star` and the inner name through the second body. |
| `hip3Star` action name writer | A second jump table of 8 entries over the tag; each entry writes a name through the str writer. Names of 32 or more bytes use `0xd9 len` and the copy slot. |
| address array writer | `neg cap` overflows only for `cap == 2^63` (streaming): tail call to the loop. Any other state is a buffered flush: array header with the count word (+0x20), each buffered byte through the uint writer, the buffer is freed when its capacity is non-zero, then the loop. |
| address array loop | The set words are `(root, height, len)`; no root means length 0. Length `>> 32 != 0` allocates a 0x80-byte buffer writer (config copied from the writer) and flushes through the finish; otherwise the array header is written with the length. Each key is rendered as 42 characters through the hex formatter and written with the str writer (`0xd9 0x2a` and a 42-byte copy). A key iterator that runs dry before the counted length ends in a panic-location slot call. |
| set iterator next | Nine-word lazy front like the map iterators of the earlier packet; keys at +8 (stride 20), parent index u16 at +0xe4, length u16 at +0xe6, edges at +0xe8. |
| hex formatter | `(buf, 42, src, 20, 0)` writes `0x` and 40 lowercase digits from a 16-byte digit table and returns `(ptr, len)`. |

`functions.tsv` has the byte hash of every body; `instructions.tsv` the instruction rows of the six new bodies (copy 1) and the formatter; `copy-shapes.tsv` shows that copies 2 and 3 have the same instruction shape (operation name, length, operand size) as copy 1 for every role; `jump-tables.tsv` the table entries; `name-table.tsv` the written bytes of every action in every copy; `slots.tsv` the relocated slots.

## Implementation and comparison

The reconstruction (`Model`: `push`, `header`, `string`, `uint`, `name`, `array`, `buffered_flush`) is plain Python over lists and byte strings. It does not read the capture. Each case builds memory (writer, item tag byte, B-tree set nodes laid out with the observed offsets), runs the original body, and compares output bytes, capacity, result word, panic kind and the ordered allocator/copy log (`alloc`, `realloc`, `memcpy`, `dealloc` with sizes). Allocation failure is planned at the n-th allocator call.

| Family | Cases |
|---|---|
| element writer (3 copies) | 7824 |
| action name writer alone (23 tags x 24 room sizes x 2 prefill sizes x 3 copies) | 3312 |
| address array writer incl. the buffered flush branch | 900 |

Total 12036 cases, 33328891 interpreted steps, 0 mismatches (`summary.json`, `all_cases_sha256` over every case outcome). Inputs vary the tag (all 23), the set shape (empty, leaf, height 1 and 2, 1 to 16 keys with shapes forcing 15, 16 and 17 keys), forged length words (+1, -1, and `2^32 + k` for the buffered branch), writer capacity and prefill length around every reserve threshold, planned allocation failures, and writer flags and config words.

Negative controls (`controls.tsv`, 45 of 45 detected, each run over the same family-spanning subset):
- 14 wrong reconstructions (swapped action names, shifted inner names, wrong wrapper key, str8 limit, header limit, uppercase hex, missing prefix, reversed addresses, wrong count, missing pair marker, reserve rules, missing copy log, allocation-failure index);
- corrupted bytes of the capture (marker and compare immediates, string immediates, table entries, the digit table, the streaming jump, hex length, key length, buffer size, count shift, iterator offsets, the str8 marker, the header limit, the reserve minimum); some are caught as refusals of the interpreter, which counts as detection;
- out-of-range inputs: wrong digest, address outside sections, short unwind extent, a tag outside the enum, and a call to an unmodelled target.

## Results and limitations

Metrics: 12036 cases, 0 mismatches; 45 of 45 negative controls detected; 46 bodies, 7286 instructions, 5290 executed; 404 non-nop instructions of the new bodies never executed (`unexecuted.tsv`); 17 unit tests.

Limits:
- The error-result branches (a non-OK result from the header, name, uint or str writer) cannot occur with a vector writer and are listed in `unexecuted.tsv`, not proven; so are the unwinding landing pads and the aligned-allocation branches.
- A buffered run (length word of at least 2^32) can only end in the iterator panic here, so the buffered finish is proven by the earlier container packet's direct cases; the flush branch of the address writer is proven through the direct `vaddr` family.
- The enum is read only through its tag byte; tags above 22 are outside the enum (the jump table index runs past the second table) and are refused, not modelled.
- Slot targets other than the hex formatter are not interpreted; only their roles in these bodies are observed.
- No progress gate is requested.

Next question: the callers that hand the `sub_deployers` list to this element writer from the Hip3 `schema` record writers, and the `val` stage writer `0x2296fa0` with its copies.
