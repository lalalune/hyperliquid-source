# dex-registry: map entry stage writers (key, value, end) and their leaf writers in node #115

This packet turns the three stage writers of the map entry writer into reconstructible pure functions: after it, the whole write of one map entry (`0x92` pair marker or in-stage array header, key as msgpack uint, value as msgpack uint, optional byte block) is a short Python model that is checked against the original bytes, in all three copy families. The previous container packet kept these stage writers as stubs, and the key and value stage writers turn out to be one and the same code (same instruction sequence, different copy address). Here 30 original bodies (three copy families, 2,748 instructions) run from their original bytes in 16,500 cases with 0 mismatches against an independent reconstruction, and all 42 negative controls (17 wrong reconstructions, 21 byte corruptions of the capture, 4 out-of-range inputs) are detected.

- Component ID: `dex-registry` (DEX metadata and clearinghouse registry; first task: recover identifiers, lookup rules and deployment ownership checks).
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No #94 material and no reference source were used.
- Claim status:
  - Observation: bytes, call targets, relocated slot targets, FDE extents and the interpreted behaviour of the listed bodies.
  - Inference: the msgpack reading of the emitted bytes (markers `0x90..0x9f`, `0xdc`, `0xdd`, `0xc4..0xc6`, `0xcc..0xcf`, positive fixint), and the names `key`, `val`, `end` (from call order of the entry writer).
  - Unresolved: which Hip3 field each stage pair serves, the error arms of the stage writers (never reached, see Limits), and the allocator/copy/panic slots.
- Scope:
  - Included (three copy families, copy 1 / 2 / 3):

    | Body | Copy 1 | Copy 2 | Copy 3 |
    |---|---|---|---|
    | map entry writer | `0x22877f0` | `0x41bf660` | `0x5315e20` |
    | key stage writer (first callee) | `0x2296160` | `0x41cfc10` | `0x53206b0` |
    | value stage writer (second callee) | `0x2296fa0` | `0x41d06f0` | `0x5320130` |
    | end stage writer (third callee) | `0x22999e0` | `0x41d4150` | `0x5325140` |
    | array header | `0x25e7c10` | `0x3d50540` | `0x57cee80` |
    | unsigned integer writer | `0x25e9f10` | `0x3d51450` | `0x57cfd20` |
    | bin header writer | `0x25e80c0` | `0x41c5b90` | `0x57cf350` |
    | vec reserve | `0x231e050` | `0x43bd910` | `0x5963a10` |
    | grow helper | `0x231dc90` | `0x43bd550` | `0x5963650` |
    | marker normaliser | `0x25eab50` | `0x3d52310` | `0x57d0b20` |

  - Ownership disclosure: the earlier container packet `dex-registry-container-writers-115` (not yet merged when this was written) names these stage writers as stubs only. `serialization-rmp-map-pairs-115` lists `0x2296160`/`0x41cfc10` as the value serializer of a different writer (`0x228b8d0`), and `RE-001-owner-tail-phases-115` and `RE-015-signed-action-rmp-encoders-115` list `0x22999e0` as a callee address. This packet reaches the same bodies through the entry writer `0x22877f0`, adds the value stage writers `0x2296fa0`/`0x41d06f0`/`0x5320130`, the end stage writers' behaviour and the entry-level byte output, and does not depend on those packets' tables.
  - Excluded: the sequence element writer `0x22927f0`, the container loops, the allocator, copy and panic GOT slots (`slots.tsv`), unwinding landing pads, the deserializer side, and any progress gate.

## Reproduce

From the repository root, with Python 3 standard library only (binutils are not needed on PATH):

```sh
python3 tools/dex_registry_entry_stages_115.py --out research/work-items/dex-registry-entry-stages-115
python3 -m unittest tests.test_dex_registry_entry_stages_115
```

How the tool works:
- It checks the capture SHA-256 first and refuses any other input.
- It reads sections through `tools/elf_index.py` (NOBITS excluded), function extents through `tools/fde_extents.py` and `R_X86_64_RELATIVE` addends from `.rela.dyn`; it imports the image reader of `tools/hip3_subrecord_helpers_115.py`.
- It derives the stage order from the first-call order of each entry writer and refuses a copy where the order or the shape of the key and value stage writers differs.
- It decodes every body with a fixed-pattern x86-64 decoder; each body must land exactly on its FDE end. It then runs the original bytes in an interpreter with ZF/CF/SF/OF. The capture is never executed and no external program is called.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical output (checked with `diff -r`). One run takes about 60 s and 265 MB.
- The tool writes `measure.json` with `cases`, `negative_controls` and `negative_detected`.

## Evidence

Coordinates are linked virtual addresses; extents are FDE `[start, end)` values.

Observed behaviour (interpreted from bytes, equal in the three copies unless stated). The stage state is five words at `rsi`: pending-prefix capacity (`2^63` means "no prefix"), prefix pointer, prefix length, writer pointer, and a u32 count.

| Body | Observed behaviour |
|---|---|
| map entry writer | Builds the state `(0 or 2^63, 1, 0, writer, 2)`: capacity 0 when the writer byte at +0x1c is 2, otherwise `2^63` after pushing the single byte `0x92`. Then calls key, value and end stage writers with that one state block. A non-OK result word is copied out and a positive state capacity would be freed. Both flag paths emit the same bytes `92 <key> <value>`; they differ in who writes `0x92`. |
| key and value stage writer | Same instruction sequence in each copy (checked as a call-target-free shape). If the state capacity is not `2^63`: write an array header with the u32 count, write each prefix byte as an unsigned integer, free the prefix when its capacity is not 0, and set the state capacity to `2^63`. Then write the 64-bit item as an unsigned integer. Because the first live stage consumes the prefix, the second stage only writes its integer. |
| end stage writer | State capacity `2^63`: return OK untouched. Otherwise, if the count is below 16 and every prefix byte is below 0x80, write an array header with the count; else write a bin header whose length is the count (not the prefix length). Then reserve for the prefix length, copy the prefix with one memcpy (skipped for length 0) and free the prefix when its capacity is not 0. |
| array header | `n < 16`: `0x90 | n`; `n < 0x10000`: `0xdc` and a big-endian u16; otherwise `0xdd` and a big-endian u32 (the marker goes through the normaliser). |
| unsigned integer writer | `< 0x80`: one byte; `< 0x100`: `0xcc` and the byte; `< 0x10000`: `0xcd` and a big-endian u16; `< 2^32`: `0xce` and a big-endian u32; else `0xcf` and a big-endian u64. The marker byte and the payload are reserved separately. |
| bin header writer | length `< 0x100`: `0xc4` and one byte; `< 0x10000`: `0xc5` and a big-endian u16; else `0xc6` and a big-endian u32. |
| reserve | `max(2*cap, len+add, 8)` through the grow helper with the alloc slot when cap is 0, else the realloc slot. |

Raw per-instruction rows are in `instructions.tsv`; `functions.tsv` has the byte hash of every body; `stage-roles.tsv` the stage callees per copy (copy 3 calls `0x53206b0` before `0x5320130`; the two are the same code, so the swap has no effect on behaviour); `slots.tsv` the relocated slots.

## Implementation and comparison

The reconstruction (`m_header`, `m_uint`, `m_bin_header`, `m_stage_uint`, `m_stage_end`, `m_entry`) is plain Python over byte strings. It does not read the capture. Each case builds memory (a writer Vec with chosen capacity, length and flag byte, a stage state block with prefix bytes, count and capacity word, and the 64-bit items), runs the original body, and compares output bytes, writer capacity, result word, the two marker bytes the leaf writers leave in the result record, state capacity word, panic kind and the ordered allocator/copy log. Only the allocator, copy, dealloc and panic slots are stubs; the leaf writers run as original code.

| Family | Cases |
|---|---|
| key stage writer (3 copies) | 3,000 |
| value stage writer (3 copies) | 3,000 |
| end stage writer (3 copies) | 3,300 |
| map entry writer with all three stages real (3 copies) | 2,100 |
| unsigned integer writer called directly (3 copies) | 2,100 |
| bin header writer called directly (3 copies) | 1,500 |
| array header called directly (3 copies) | 1,500 |

Total 16,500 cases, 3,873,096 interpreted steps, 0 mismatches (`summary.json`, `all_cases_sha256` over every case outcome; `cases.tsv` lists every 10th case). Inputs vary the prefix capacity (`2^63`, 0, 1, 3, 8, 0x80, 0x100), prefix bytes (below 0x80, any, edge values 0, 0x7f, 0x80, 0xff), the count (0 to 17, 255, 256, 0xfffe to 0x10001, 0xffffffff), the items (0, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xffffffff, 2^32, 2^63, 2^64-1 and random), writer capacity (0 to 64), length and flag, and planned allocation failures. The leaf writers (integer, bin header, array header) also run alone with values up to 2^64-1 and lengths up to 0xffffffff, which reaches their wide-value and reserve branches.

Negative controls (`controls.tsv`, all 42 detected, subset of 1,097 family-spanning cases each):
- 17 wrong reconstructions (header limit, endianness and marker; integer fixint limit, uint8 marker, uint16 endianness; reserve rules; missing prefix free, free of an empty prefix, state not consumed; end-stage array limit, signed byte scan, bin length from prefix length, missing memcpy; entry marker and flag skip);
- 21 corrupted bytes of the capture (integer thresholds and markers in the three copies, stage result compare and OK word, end-stage count limit and byte scan, bin markers and limits, entry state count and marker, header limit, reserve minimum);
- 4 out-of-range inputs (wrong digest, address outside sections, overlong unwind extent, call to an unmodelled target).

An earlier control that flipped the entry flag compare was removed as an equivalent mutant: both flag paths produce the same bytes.

## Results and limitations

Metrics: 16,500 cases, 0 mismatches; 42 of 42 negative controls detected; 30 bodies, 2,748 instructions, 2,436 executed; 312 non-nop instructions never executed (`unexecuted.tsv`); 20 unit tests.

Limits:
- The stage writers' error arms (a callee result other than OK) and the entry writer's cleanup arms are never reached, because the real callees only return OK or do not return (allocation failure ends in the alloc-error slot). They are listed in `unexecuted.tsv` but not classified row by row, together with unwinding landing pads and the unreached parts of the grow helper and marker normaliser.
- The pending-prefix state is always built by the entry writer with an empty prefix and count 2. Non-empty prefixes and other counts are only exercised by calling the stage writers directly with a hand-built state, so no caller that supplies such a state is established.
- The semantic roles (key, value) are inference from call order; what Hip3 field the pair carries is not shown here.
- Slot targets are not interpreted; only their roles in these bodies are observed.
- No progress gate is requested.

Next question: the sequence element writer `0x22927f0` and its copies (`0x41c2c30`, `0x5312380`), and who builds a non-empty prefix state for the stage writers.
