# RE-016: MessagePack marker front end of the state-file decoder at 0x3266520, rebuilt and checked against its bytes

With this packet the 5,239-byte function at VA 0x3266520 (node #115) can be re-implemented as a pure function: given the slice reader (pointer, unread count, cached-marker tag and payload) and the following bytes, `model()` in `tools/re16_rmp_dispatch115.py` predicts which of four external bodies is entered, with which argument registers, how many bytes the reader consumed, or which 16-byte error record is written. The emulator running the real bytes agrees with the model on all 10,555 generated cases.

- Component ID: abci (RE-016 state materializer call chain); `l1/abci/state.rs` is only a reference hint. The names "MessagePack front end" and "rmp-style Deserializer" are inferences.
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main at the time of the run (shared emulator `tools/re16_state_materialize115.py` and `tools/fde_extents.py` imported, not copied); no reference source copied. #94 results were not used.
- Claim status: observation (dispatch, argument registers, reader state, error records, jump table) plus inference (names, the meaning of tag 1 and of the payload byte).
- Scope included: the front end only, i.e. everything the function does before its first external call, plus the error returns. Excluded: the four external bodies (0x341ff00 through GOT slot 0x64e4220, 0x1681e40, 0x16815e0, 0x2f909a0), the code after them (the function's second half that consumes their results), and the other GOT calls (64df480 etc.) that the later phases use. No progress gate is requested.

## Reproduce

From the repository root, with the node binary at `artifacts/node/115/hl-node`:

    python3 tools/artifacts.py verify
    python3 tools/re16_rmp_dispatch115.py --out research/work-items/RE-016-rmp-front-end-115
    python3 -m unittest tests.test_re16_rmp_dispatch115

The tool checks the binary SHA-256 first, reads ELF bytes through the repository interpreters (`elf_index`, `fde_extents` via the merged emulator module), never runs the binary and never calls an external program. Output is deterministic (about 20 s, well below 1 GB). `MANIFEST.sha256` lists every file here except itself.

## Evidence

All addresses are virtual addresses of the .text/.rodata image.

- The unwind record gives exactly [0x3266520, 0x3267997); `summary.json` records 1,140 decoded instructions with the repository decoder (patched in the tool for the `66 c7`/`66 81` imm16 forms).
- `call_sites.tsv`: 64 call/jump sites that leave or dispatch inside the function (direct calls, GOT calls with the slot, four register jumps).
- `jump_table.tsv`: the 256-entry int32 table at 0x70087c (relative to the table), read from the file bytes. 28 distinct targets; 188 entries point at the trap at 0x326787c (tags 1..0x7f except the fixint tag 0, tags 0x81..0x8f, 0x91..0x9f, 0xa1..0xbf); entries for 0xe1..0xff point at unrelated blocks and are outside the normalised tag set the function itself produces.
- Reader layout (inference confirmed by 10,555 runs): +0x10 pointer, +0x18 unread count, +0x20 cached tag (the function stores 1 here on entry; 1 means nothing cached), +0x21 cached payload.
- Normalisation done when a marker is read fresh: byte b becomes (0, b) below 0x80; (0x80, b&15) for fixmap; (0x90, b&15) for fixarray; (0xa0, b&31) for fixstr; (b, b&31) for 0xc0..0xdf; (0xe0, b) from 0xe0. Fixint, fixmap, fixarray and fixstr use a fast path (the handler-address register r8 stays 0); everything else goes through the table, which leaves the handler address in r8 and the table address in rcx.
- Outcomes (`summary.json`, over 10,555 cases): invalid_type 5,502; container 2,037; str_body 309; bin_body 99; returned error records 1,528; trap 1,080.
- Per tag: kind-only tags (0xc0, 0xc2, 0xc3, 0xca..0xd3, 0xe0 and fixint) call 0x341ff00 with (out, reader, kind, value); fixmap/fixarray/fixext/ext/array/map call 0x1681e40 with a static descriptor (0x6464fa8 map, 0x6464f78 array, 0x6464f60 ext), the payload in rsi and the count in rdx (0xdd keeps its count in ebp); strings (fixstr, 0xd9..0xdb) call 0x16815e0 with the string pointer, length and unread rest; 0xc4..0xc6 call 0x2f909a0 with the unread rest. Length words are big-endian; a short length word consumes the rest of the input and writes tag byte 1 and the pointer 0x64622f0; an over-long length writes the record (1, 3, 0x25) and keeps the reader after the length word; 0xc1 writes (2, 0xc1).
- Case data are in `cases.tsv` (one row per case: reader state, input bytes, observed outcome).

## Implementation and comparison

`model(tag, aux, data, table)` is the rebuilt front end. `Rig.run` executes the real function on the emulator with every external target replaced by a halting stub and reads the arguments from the registers at the first external call. Cases (`all_cases`): every marker byte 0..255 read fresh with 24 data shapes each (empty, short, exact-length, over-long, random), the empty input, and cached states for 5 fix/kind tags, all of 0xc0..0xdf and 12 trap tags, with 9 payload values and 10 data shapes. Controls (`controls.tsv`): 13 wrong models, 13 single-bit condition flips in the function's own conditional jumps (59 candidates were tried; the other 46 flips are not visible on this grid and are not counted), 4 corrupted table entries, 3 out-of-domain cached tags, a flipped and a truncated binary, and a read outside the file-backed sections. No Rust implementation is part of this packet ("not yet implemented").

## Results and limitations

- `measure.json`: 10,555 cases, 0 mismatches; 36 negative controls, 36 detected.
- The model covers only the first external call or the early return. What the function does with the returned values is not modelled and the stubs return nothing meaningful, so the second half (the large tail with the GOT calls at 64df480..64df848) remains unresolved.
- The roles of the four external bodies are inferred from their arguments only.
- Cached tags 0xe1..0xff and the trap tags are exercised only as far as the machine reaches (trap tags); the table entries for 0xe1..0xff lead to blocks whose purpose is unresolved.
- Next question: model the tail of 0x3266520 (the code after 0x1681e40 and 0x16815e0 return) and the callee 0x1681e40's use of the three static descriptors.
