# dex-registry: Hip3 sub-record field helpers in node #115

This packet makes the outlined field helpers of the node #115 `Hip3` `limits`, `schema` and `state` records reconstructible as pure functions. That completes the msgpack writing path below those three records except for the container writers it calls. It covers:
- the `asset_to_oi_cap` map entry, including the exact nine-word iterator it builds from a niche-tagged two-representation container (ring-buffer slices or root/height/length);
- the `sub_deployers` tail call and the `max_n_users_with_positions` u64 field;
- the bool marker, the nil byte and the 20-byte address rendering;
- the `Time` newtype with its rmp `_ExtStruct` rejection (`expected tuple`);
- the copy-2 `Time` that is instead rendered as text (date, `'T'`, time) through `fmt::Write` and panics on a formatter error.

All 21 helper bodies (three copy families) were interpreted from their original bytes in 5,508 cases with 0 mismatches against an independent reconstruction, and all 18 deliberately wrong reconstructions are caught.

- Component ID: `dex-registry` (DEX metadata and clearinghouse registry; first task: recover identifiers, lookup rules and deployment ownership checks).
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`. No #94 material and no reference source were used.
- Claim status:
  - Observation: bytes, call targets, relocated slot targets, key and error literals, and interpreted behaviour.
  - Inference: the serde/rmp/chrono/VecDeque reading and the domain meaning of the field names.
  - Unresolved: the internals of the stubbed callees (map, sequence, u64, str, newtype, ext, hex, formatters, dealloc, panic, grow).
- Scope:
  - Included, listed per helper:

    | Helper | Copy 1 | Copy 2 | Copy 3 |
    |---|---|---|---|
    | `asset_to_oi_cap` map | `0x2ce96a0` | `0x44f7950` | `0x5676d60` |
    | `sub_deployers` | `0x2ce6f90` | `0x44f8ed0` | `0x56746c0` |
    | `max_n_users_with_positions` | `0x2cea920` | `0x44fbf10` | `0x5676b40` (keyed variant) |
    | bool | `0x226a340` | `0x4199740` | `0x52f0010` |
    | nil | `0x226a3b0` | `0x41997b0` | `0x52f0170` |
    | Some(address) | `0x226a510` | `0x4199dc0` | none |
    | `Address` newtype | none | none | `0x52f15d0` |
    | `Time` | `0x226cf70` | `0x41b0e20` (text) | `0x52f9680` |

    Also included: the relocated slots `0x64e4d08`, `0x64e1158`, `0x64e1160`, `0x6482118` (String vtable `+0x20`), `0x64df4a0` and `0x64df6a0`.
  - Excluded:
    - The internals of every callee listed in `callee-roles.tsv`.
    - Unwinding landing pads (the copy-2 `Time` cleanup pad after a panic).
    - The deserializer side.
    - Any progress gate.

These helpers are the stubbed roles of the Hip3 record serializers (`callee-roles.tsv` of packet `dex-registry-hip3-limits-schema-state-115`):
- `limits` calls the users-cap helper.
- `schema` calls the oi map, `sub_deployers`, Some/None and `Address` helpers.
- `state` calls the bool (`m`) and `Time` helpers.

## Reproduce

From the repository root, with Python 3 standard library only (binutils are not needed on PATH):

```sh
python3 tools/hip3_subrecord_helpers_115.py --out research/work-items/dex-registry-hip3-subrecord-helpers-115
python3 -m unittest tests.test_hip3_subrecord_helpers_115
```

How the tool works:
- It checks the capture SHA-256 first and refuses any other input.
- It reads section headers through `tools/elf_index.py`, excluding NOBITS sections. It reads function extents through `tools/fde_extents.py` and `R_X86_64_RELATIVE` addends from `.rela.dyn`.
- It decodes each body with a fixed-pattern decoder for a closed x86-64 subset and interprets the original bytes. The capture is never executed and no external program is called.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical output. The output contains no time, randomness or absolute path.

## Evidence

Coordinates are linked virtual addresses. Extents are FDE `[start, end)` values from `.eh_frame`. Every decoded byte count equals the FDE byte count (`functions.tsv`, 1,161 instructions in total).

The writer is `(cap, ptr, len)` with the struct-as-map byte at `+0x1b`, called `flag` below. Result words are `0x8000000000000004` for Ok. On error they are `(0x8000000000000000, e0, e1)`, or the three callee words copied through.

| Helper | Observed behaviour (interpreted from bytes) |
|---|---|
| oi map | If `flag != 0`, write `0xaf` + `asset_to_oi_cap` (two overlapping imm64 stores, reserve when room < 15). Then call the map writer with `(out, writer, &iter)`, where `iter` is nine words built from the four container words `w0..w3`. |
| `sub_deployers` | If `flag == 1`, write `0xad` + `sub_deployers`. Then tail-jump to the sequence writer with `(out, value, writer)`. |
| users cap, copies 1/2 | If `flag != 0`, write `0xba` + the 26-byte key from two rodata 16-byte loads (`0x60d376`/`0x60d380` and `0x7d29ba`/`0x7d29c4`). Then `u64(stack, writer, value)`. A u64 result of 2 maps to Ok; otherwise `(NICHE, e0, e1)`. |
| users cap, copy 3 | If `flag != 0`, call the str writer with the caller's `(ptr, len)` key and map a failure to `(NICHE, rax, rdx)`. Then call the u64 writer with `r8`. |
| bool | Reserve one byte, call `Marker::to_u8(0xc2 \| b)`, store the byte, return Ok. |
| nil | Store `0xc0`, return Ok. |
| Some(address) | `hex(stack buf, 42, value, 20, 0)` through GOT slot `0x64e4d08` (target `0x2eabb50`), then `str(writer, buf, 42)`. |
| `Address` / `Time` newtype | Compare the newtype name with `_ExtStruct` (length 10, imm64 + imm16). Not ext: render or delegate normally. Ext: the address helper renders and then returns `(NICHE+2, "expected tuple", 14)`. The `Time` helper calls the ext writer and turns its success into the same error, passing ext failures through. |
| `Time` text (copy 2) | Build a `String` and a `Formatter` (vtable `0x64820f8`, options `0x60000020`). Call the date formatter (`[[rdx]]`), `write_char('T')` via vtable `+0x20` and the time formatter (`[[rdx]]+4`). Write the text with the str writer, then free the buffer. Any formatter error panics with `a Display implementation returned an error unexpectedly` (55 bytes at `0x7c66c0`). |

The `oi_map` iterator (all values wrap at 64 bits, `B = w1` buffer, entries are 16 bytes):
- `w0 == i64::MIN`: `p = (w1 != 0)`, `iter = (p, 0, w1, w2, p, 0, w1, w2, w1 ? w3 : 0)`.
- Otherwise, with `cap = w0`, `head = w2` and `len = w3`:
  - If `len == 0`: `iter = (2, B, B, B, B, 0, B, B, 0)`.
  - Else let `phys = head - (head >= cap ? cap : 0)` and `room = cap - phys`.
    - If `len > room`: `iter = (2, B+16*phys, B+16*cap, B, B+16*(len-room), 0, B+16*cap, B, len)`.
    - Otherwise: `iter = (2, B+16*phys, B+16*(phys+len), B, B, 0, B+16*(phys+len), B, phys+len)`.

The evidence files are:
- `functions.tsv`: extents and digests.
- `instructions.tsv`: every decoded instruction.
- `callee-roles.tsv`: role, call style (direct, GOT slot, vtable slot, tail jmp), target and site count for each callee. The tool rejects any body whose call targets differ from the role table.
- `relocated-slots.tsv`: each slot's `.rela.dyn` file offset and addend.
- `literals.tsv`: inline markers, imm64 key fragments, rodata loads and rip-relative texts.
- `texts.tsv`: the reconstructed keys and the error and panic texts read back from the bytes.
- `cases.tsv`: one row per case with the input, failing call, appended bytes, call log, end length, result words and verdict.
- `paths.tsv`, `negative-controls.tsv` and `summary.json`.

## Implementation and comparison

The implementation is `recon()` and `oi_iterator()` in `tools/hip3_subrecord_helpers_115.py`. These are standard-library pure functions that return the appended bytes, the ordered callee calls with their arguments, the final writer length and the three result words.

The comparison runs the original bytes of each body in the interpreter. Callees are stubbed by role:
- Stubs record their arguments. Stack references are dereferenced: the nine iterator words, and the `**value` chains.
- Success or failure of each counted call is scripted.
- Formatter stubs append fixed text to the in-memory `String`.

| Kind | Bodies | Cases | Inputs swept |
|---|---|---|---|
| oi map | 3 | 3,426 | 4 flags × key slack 0..39 (flag 1) × failing map; 1,050 container shapes (8 capacities × all heads up to `2·cap+1` × lengths up to `cap+1`, 64-bit edge values, niche roots) |
| `sub_deployers`, users cap | 5 | 471 | 4 flags × key slack × failing call |
| bool | 3 | 1,536 | all 256 byte values × full/non-full writer |
| nil, Some, `Address`, `Time` | 9 | 75 | names `Time`, `Address`, `_ExtStruct` and four near-misses × failing call; 4 failing points for the text `Time` |

All 5,508 cases match. The 43 paths in `paths.tsv` include every Ok exit, every error exit and the three panic exits of the text `Time`.

Negative controls (`negative-controls.tsv`): 18 wrong reconstructions, each caught in at least 2 cases:
- inverted key gates for all three keys;
- an inclusive reserve check;
- an inclusive ring-wrap test;
- the last iterator word taken as the length;
- the niche ignored, or its presence bit inverted;
- marker base `0xc0`, or the marker computed before the reserve;
- ext success passed through, or an ext-name check on 9 bytes only;
- a u64 error copied as three words;
- the copy-3 key written inline;
- `' '` as the `Time` separator, time before date, a formatter error returned instead of a panic, or the String not freed.

The unit test also patches single instructions in the capture (key gates, `ja`→`jae`, marker `0xc2`→`0xc0`, the `_ExtStruct` immediate, the `'T'` immediate, the Ok word). It checks that the interpreted result then departs from the reconstruction.

## Results and limitations

Results:
- 21 bodies, 5,508 of 5,508 cases matching and 18 of 18 negative controls caught.
- Copy differences recovered from the bytes:
  - The copy-3 users-cap helper receives its key from the caller.
  - The copy-3 schema uses an `Address` newtype helper that rejects `_ExtStruct`.
  - The copy-2 `Time` is serialized as text, while copies 1 and 3 use a newtype call.

Limitations:
- The callee internals are stubbed. The claim is the helper bodies' own control flow, constants, argument wiring and result mapping.
- Container shapes outside VecDeque invariants (`head >= cap`) are included as arithmetic checks only.
- The formatter text is a stub choice. The claim is the order (date, `'T'`, time), the String handling and the panic.
- Inference only, not proved here: the ring buffer is a `VecDeque` and the niche form a `BTreeMap`; the date/time formatters are chrono's; `0x2eabb50` is a hex encoder.
- No progress gate is changed.
