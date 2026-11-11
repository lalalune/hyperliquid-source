# dex-registry: msgpack stage writers (key, value, end, tuple, sequence element) and the full map write path in node #115

This packet makes the write path of the Hip3 `asset_to_oi_cap` map reconstructible end to end as pure functions: the map loop, the entry writer, the key, value and end stage writers, the unsigned-integer writer and the array-header writer now run from their original bytes with no stubbed role, so the wire form of the map (an array of `[key, value]` pairs of msgpack unsigned integers) is known byte for byte, including the buffered-state flush rule, the array-versus-binary choice of the end stage and the integer width table. The sequence side (`sub_deployers`) is reconstructed down to two role stubs: the enum-variant name writer and the address-set writer. In 12,840 cases (three copy families, 21 new bodies and 33 integrated bodies, 5,632 instructions) the original bytes agree with an independent reconstruction and with an independent msgpack reader of the produced bytes, with 0 mismatches, and all 54 negative controls are detected.

- Component ID: `dex-registry` (DEX metadata and clearinghouse registry; first task: recover identifiers, lookup rules and deployment ownership checks).
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No #94 material and no reference source were used.
- Claim status:
  - Observation: bytes, call targets, relocated slot targets, FDE extents and the interpreted behaviour of the listed bodies.
  - Inference: the msgpack reading (positive fixint, `0xcc`..`0xcf`, array and `0xc4`..`0xc6` binary markers), the names of the writers and of the five-word stage state, and the reading of the item words as unsigned 64-bit integers.
  - Unresolved: the enum-variant name writer, the address-set writer (both role stubs), the unwinding landing pads, the allocator, copy and panic slots.
- Scope:
  - Included, new bodies (copy 1 / 2 / 3):

    | Body | Copy 1 | Copy 2 | Copy 3 |
    |---|---|---|---|
    | key stage | `0x2296160` | `0x41cfc10` | `0x53206b0` |
    | value stage | `0x2296fa0` | `0x41d06f0` | `0x5320130` |
    | end stage | `0x22999e0` | `0x41d4150` | `0x5325140` |
    | tuple stage | `0x2299050` | `0x41d3d00` | `0x53207f0` |
    | sequence element writer | `0x22927f0` | `0x41c2c30` | `0x5312380` |
    | unsigned integer writer | `0x25e9f10` | `0x3d51450` | `0x57cfd20` |
    | binary header writer | `0x25e80c0` | `0x41c5b90` | `0x57cf350` |

  - Included, integrated unchanged from the container-writers work (they run as real code under the new bodies): map and sequence loops, entry writer, array header, marker normaliser, vec reserve and grow helper, the two iterator `next` bodies, finish and the sequence wrapper (listed in `functions.tsv`; their own evidence is not repeated here).
  - Role stubs: enum-variant name writer (`0x2bc7610`, `0x44a3da0`, `0x54a20a0`) and address-set writer (`0x2228ba0`, `0x4152580`, `0x52808c0`, reached by a tail call from the tuple stage).
  - Excluded: the stubbed roles above, unwinding landing pads, the deserializer side, and any progress gate.

## Reproduce

From the repository root, with Python 3 standard library only (binutils are not needed on PATH):

```sh
python3 tools/dex_registry_stage_writers_115.py --out research/work-items/dex-registry-stage-writers-115
python3 -m unittest tests.test_dex_registry_stage_writers_115
```

How the tool works:
- It checks the capture SHA-256 first and refuses any other input.
- It reads sections through `tools/elf_index.py` (NOBITS excluded), function extents through `tools/fde_extents.py` and `R_X86_64_RELATIVE` addends from `.rela.dyn`; it imports the image reader of `tools/hip3_subrecord_helpers_115.py`. Roles are derived from call order inside the original bodies (`stage-roles.tsv`), so a wrong address cannot be pinned by hand.
- It decodes every body with a fixed-pattern x86-64 decoder; each body must land exactly on its FDE end. It then runs the original bytes in an interpreter with ZF/CF/SF/OF. The capture is never executed and no external program is called.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical output (checked with `diff -r`). One run takes about 140 s and 260 MB.
- The tool writes `measure.json` with `cases`, `negative_controls` and `negative_detected`.

## Evidence

Coordinates are linked virtual addresses; extents are FDE `[start, end)` values.

Observed behaviour (interpreted from bytes, equal in the three copies unless stated):

| Body | Observed behaviour |
|---|---|
| unsigned integer writer | Value below `0x80`: one byte, the value itself. Below `0x100`: `0xcc` and the byte. Below `0x10000`: `0xcd` and a big-endian u16. Below `2^32`: `0xce` and a big-endian u32. Otherwise `0xcf` and a big-endian u64. Every write reserves first when the room is smaller than the write (1 byte for a marker, 2, 4 or 8 for the payload). The result is the word 2 followed by the marker byte at +8 (zero for a fixint, whose value is the byte at +9). |
| binary header writer | Length below `0x100`: marker `0xc4` and one byte. Below `0x10000`: `0xc5` and a big-endian u16. Otherwise `0xc6` and a big-endian u32. The marker goes through the marker normaliser (`0xc0..0xdf` pass). Result: the word 2 and the marker byte at +8. |
| stage state | Five words `(cap, ptr, len, writer, hint)`, the hint a u32 at +0x20. Capacity word `2^63` means streaming (nothing pending). Any other value is a buffered state: `ptr/len` hold pending bytes, `cap` is the allocation size (0 for an empty buffer). |
| key stage and value stage | Identical bodies. Buffered state: write an array header with the hint, then every pending byte as an unsigned integer, free the buffer when `cap != 0`, set the state capacity to `2^63`. Then write the item (a u64 read through the item pointer) as an unsigned integer. Success is the word `2^63 + 4`; a failing callee turns into `(2^63, code, word)` and leaves the state and the buffer untouched. |
| tuple stage | The same flush as the key stage, then a tail call of the address-set writer with the writer and the item pointer; its result words are returned unchanged. |
| end stage | Streaming state: success. Buffered state: pick the array header (hint below 16 and every pending byte below `0x80`) or the binary header (otherwise, without scanning when the hint is 16 or more), write it with the hint, reserve and copy the pending bytes, free the buffer when `cap != 0`. A failing header frees the buffer too and returns `(2^63, code, word)`. |
| sequence element writer | Push `0x92` unless the writer flag byte at +0x1c is 2; flag 2 writes an array header of 2 through the header writer instead. Then call the variant writer, the tuple stage on a fresh streaming state `(2^63, 1, 0, writer, 2)` and the end stage. The first non-OK result is copied out. |
| map entry (entry writer from the earlier packet, now with real stages) | Push `0x92` unless the flag byte is 2. The state starts as `(0, 1, 0, writer, 2)` for flag 2 (so the key stage writes the pair header) and as streaming otherwise. Key stage, value stage, end stage. |
| map wire form | `header(n)`, then per entry `0x92`, `uint(key)`, `uint(value)`. |

Raw per-instruction rows of the new bodies are in `instructions.tsv`; `functions.tsv` has the byte hash and executed count of every body, `stage-roles.tsv` the role derivation, `slots.tsv` the relocated allocator, copy and panic slots, and `unexecuted.tsv` every non-nop instruction of a new body that no case reached.

Copy differences (sizes in bytes / instructions, from `functions.tsv`):

| Body | Copy 1 | Copy 2 | Copy 3 |
|---|---|---|---|
| key stage and value stage | 319 / 87 each | 319 / 87 each | 319 / 87 each |
| end stage | 324 / 96 | 324 / 96 | 324 / 96 |
| tuple stage | 287 / 80 | 287 / 80 | 287 / 80 |
| sequence element writer | 453 / 109 | 453 / 109 | 453 / 109 |
| unsigned integer writer | 901 / 240 | 901 / 240 | 901 / 240 |
| binary header writer | 349 / 92 | 410 / 107 | 349 / 92 |

- Only the binary header writer of copy 2 has a different layout (61 bytes and 15 instructions more). All 330 binary header cases per copy give the same bytes in all three copies, so the layout difference does not change the observed behaviour.
- The stage bodies of one copy have equal size but different byte hashes (relocated displacements and call targets differ); the address order of key and value is swapped in copy 3 (`stage-roles.tsv`).
- The tuple stage ends in a tail call (`jmp`) to the address-set writer in every copy; the interpreter runs it as a call and a return.

## Implementation and comparison

Besides the byte model, every successful map run is read back by `decode_wire`, a separate msgpack reader (arrays and unsigned integers only), and must decode to the list of `[key, value]` pairs that were put in memory; a model bug that agrees with a wrong body cannot hide there. The reconstruction (`m_uint`, `m_binhdr`, `m_flush`, `m_key`, `m_tup`, `m_end`, `m_elem2`, `m_entry2`, `m_loop2`) is plain Python over lists and byte strings. It does not read the capture. Each case builds memory (writer, stage state, pending buffer, item words, iterator slices or B-tree nodes), runs the original body, and compares result words, result bytes, the state capacity word, output bytes, writer capacity, the ordered call log (allocator, copy and free calls; role-stub calls with their arguments) and the panic kind. Two modes exist: `real` (the integer and header writers run as original code and the model writes bytes) and `stub` (the integer, array-header and binary-header writers are role stubs that record the call and can fail the k-th call; this reaches every error branch, which the real leaf writers can never take).

| Family | Cases |
|---|---|
| integer writer (3 copies) | 1,800 |
| binary header writer | 990 |
| key stage | 900 |
| value stage | 900 |
| tuple stage | 1,200 |
| end stage | 1,350 |
| sequence element writer | 1,800 |
| map loop with real stages | 1,350 |
| sequence loop with real element writer | 1,200 |
| container words, sequence wrapper, sequence loop, element writer | 1,350 |

Total 12,840 cases, 6,535,450 interpreted steps, 0 mismatches (`summary.json`, `all_cases_sha256` over every case outcome). Inputs cover all integer width classes and the edges `0x7f/0x80`, `0xff/0x100`, `0xffff/0x10000`, `2^32-1/2^32`, writer room of 0 to 10 and 16 bytes, hints 0 to 31 and up to `2^32-1`, buffered states with 0 to 6 pending bytes (ASCII-only and not), planned allocation failures, planned stage failures, flags 0, 1, 2, 3, `0x80`, `0xff`, slices of 0 to 6 items and B-trees of height 0 to 2.

Negative controls (`controls.tsv`, all 54 detected, each run on the same family-spanning subset of 4,008 cases):
- 21 wrong reconstructions (header limit and endianness, reserve rules, integer fixint limit, little-endian u16, wrong u32 marker, binary limit and endianness, no free after flush, reversed flush, state kept after flush, hint ignored, no flush in the tuple stage, any-byte ASCII test, wrong hint limit, no free after a failed header, copy of an empty buffer, flag-2 push, swapped key and value, reversed wrapper slices);
- 28 corrupted bytes of the capture (integer thresholds, shift, marker, room tests, binary thresholds, markers, byte swap, header-result compares, OK words, hint load, writer load, ASCII test, flag compare, pair marker, header size, wrapper slice scale, finish OK word); some are caught as refusals of the interpreter (read of an unset byte), which counts as detection;
- 5 out-of-range inputs (wrong digest, address outside sections, short unwind extent, call to an unmodelled target, call through an unmodelled allocator slot).

## Results and limitations

Metrics: 12,840 cases, 0 mismatches; 54 of 54 negative controls detected; 54 bodies, 5,632 instructions, 4,572 executed; 69 non-nop instructions of the new bodies never executed (`unexecuted.tsv`); 21 unit tests.

Limits:
- The 69 unexecuted rows are 3 times 23: the unwinding landing pads of the end stage (9 rows) and of the element writer (9 rows), and the element writer's drop of a non-streaming state (5 rows: pointer load, size load, alignment clear, free call, jump). The drop is not reachable from this caller because the state it builds always has capacity `2^63` (inference from the bytes; no case can reach it). They are listed, not classified instruction by instruction.
- The sequence wrapper now runs in the container-wrapper family (ring buffers of 1 to 6 slots with head offsets, and B-trees of height 0 to 2); the finish routine runs only its streaming return (23 of 91 rows). `instructions.tsv` also lists these two bodies.
- The buffered branch of the loops (a length word of at least `2^32`) is not reached; the buffered stage states are tested through the stage writers directly.
- The variant name writer and the address-set writer are role stubs; the wire form of the sequence is therefore known up to those two writers. The names `key`, `value` and the reading of the items as `u64` are inference.
- Slot targets are not interpreted; only their roles in these bodies are observed.
- No progress gate is requested.

Next question: the enum-variant name writer (`0x2bc7610` and its two copies, a jump table over variant tags) and the address-set writer (`0x2228ba0` and its copies, which iterate a B-tree set and hex-encode 20-byte keys through a relocated function slot).
