# RE-010: reconstruct the MessagePack value `deserialize_any` behind the Action enum decoders

This packet makes the value-level rmp_serde `deserialize_any` of node #115
reconstructible: `reconstructed_any` in the tool is an executable model of the
three 2264-byte copies (0x1b38990, 0x32a6050, 0x491de60) that the `Action` enum
decoders call, and it now decides, for any input bytes, peeked marker, depth
budget, `cl` flag and visitor result, which visitor runs with which arguments,
how much input is consumed, how the depth budget moves, and which of the eight
error forms (or panics) comes back. That model matches the original bytes of
all three copies on every case (0 mismatches).

- Component ID: action-dispatch (task RE-010)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: lalalune/hyperliquid-source main
  `05bc2de303c05525b71e7e257426e741bc66a390`; no reference source was used
  (references/can1357-hl has no rmp_serde body).
- Claim status: observation (bytes, tables, interpreted behaviour of the
  original instructions), inference (role names of callees, the meaning of the
  40-byte Ok value), unresolved (callee bodies).
- Scope included: the three copies end to end (marker read, every jump-table
  arm, all failure branches, depth bookkeeping, the remaining-count check and
  value drop, the UTF-8 fallback). Excluded: bodies of callees (visit_map
  0x1fb1750, visit_seq 0x1fb1d20, bytes_seq 0x1fb1e50, ext visitor 0x21d1ac0,
  visit_bytes 0x21d1070, visit_str 0x21d2080, drops 0x18a33d0/0x189f500/
  0x18998a0, the `any` helper behind GOT 0x64e4198), the callers (Action enum
  decoders 0x2bd6140 / 0x36b6980 / 0x4d8bd80, already listed in the merged
  `RE-010-start-fee-trial-115` packet) and landing pads.

## Reproduce

```
python3 tools/re010_action_msgpack_struct_any_115.py --out research/work-items/RE-010-action-msgpack-struct-any-115
python3 -m unittest tests.test_re010_action_msgpack_struct_any_115
```

Python 3 standard library plus the repository parsers `tools/elf_index.py`
(sections) and `tools/fde_extents.py` (eh_frame records, uleb). The tool checks
the input SHA-256 first and fails on any other binary. It never runs the
binary and calls no external program: every number in the evidence files is
read from ELF bytes (section headers, FDE extents, LSDA call-site tables,
jump tables, `.rela.dyn` RELATIVE and `.rela.plt` JUMP_SLOT relocations) or
produced by interpreting the original instruction bytes. Output is
deterministic (no time, random or path data); the full run takes a few
minutes because of the image-mutant sweep.

## Evidence

Coordinates are virtual addresses of node #115; `off` columns are offsets from
each copy's start.

Function boundaries and copies (`copies.tsv`): each copy is exactly one FDE of
2264 bytes with an LSDA, 531 instructions decoded by a fixed-pattern subset
decoder with no undecoded byte. The three copies are the same instruction
stream byte for byte once rel32/disp32 fields are zeroed, use identical
jump-table arm offsets, and each has exactly one direct caller:

| copy | start | caller call site | caller FDE |
|---|---|---|---|
| C1 | 0x1b38990 | 0x2bd6198 | 0x2bd6140 (9014 B) |
| C2 | 0x32a6050 | 0x36b69d8 | 0x36b6980 (8964 B) |
| C3 | 0x491de60 | 0x4d8bdd8 | 0x4d8bd80 (8989 B) |

Calling convention observed in the bytes: rdi = 48-byte out
`Result<T, rmp_serde::decode::Error>` (qword 0 = Ok + 40-byte value, qword 1 =
Err + 32-byte error), rsi = deserializer (input ptr +0x10, remaining +0x18,
peeked marker tag +0x20 where 1 = none, payload +0x21, depth u16 +0x22),
rdx = visitor pointer (32 bytes; copied to the stack for str/bin/ext arms),
cl = a bool that only the bin arms read.

Jump tables (`tables.tsv`): marker table 0x574374 (225 entries, 17 arm
groups, 188 non-Marker tags to one ud2), ext table 0x5746f8 (18 entries from
tag 0xc7). The table layout equals the 1769-byte identifier decoder of the
sibling packet, but every arm body differs (out size, visitor argument,
remaining-count check, UTF-8 fallback result).

Behaviour (each rule is a branch of `reconstructed_any` and is exercised by
cases):

| marker | rule |
|---|---|
| no input | Err InvalidMarkerRead (tag 0) with the static EOF error 0x641ccb0 |
| 0x00-0x7f, 0xe0-0xff, nil, bool, int, float (15 tags) | GOT `any` helper (out, des, visitor, tag, payload); its 48 bytes are returned |
| 0xc1 | Err TypeMismatch(0xc1) |
| fixstr / str8/16/32 | length read (short length = data EOF, multi-byte reads consume the rest); body shorter than length = io Simple(UnexpectedEof) 0x2500000003; valid UTF-8 -> visit_str(out, visitor copy); invalid -> visit_bytes(tmp); Ok is forwarded, Err is dropped (0x189f500) and Err Utf8(valid_up_to, error_len) is returned |
| bin8/16/32 | same length rules; cl != 0 -> visit_bytes(out, visitor copy); cl == 0 -> bytes_seq(out, visitor, {start,end,0}) |
| fixmap/map16/map32, fixarray/array16/array32 | depth 0 -> sub-overflow panic; depth-1 == 0 -> Err DepthLimitExceeded (depth stays decremented); visit_map/visit_seq(tmp, visitor, {des,len}); visitor Err -> returned without restoring depth; remaining 0 -> Ok value; remaining > len -> sub-overflow panic (0x641fa10 map / 0x641f9e0 seq); otherwise Err LengthMismatch(len - remaining) and the value is dropped (0x18a33d0); then depth+1, with an add-overflow panic at 0xffff |
| fixext1..16, ext8/16/32 | depth rules as above; ext visitor(tmp, visitor copy, {des,len,0}); its 48 bytes are returned after depth+1 from the depth the visitor left |

## Implementation and comparison

Rust implementation: not yet implemented. The comparison is between the
pure Python model `reconstructed_any` and an interpreter that executes the
original instruction bytes of each copy with contract stubs for every callee
(stubs check argument shapes: deserializer pointer, visitor pointer or a
byte-equal stack copy, input offsets, lengths, the access structs).

Every case compares the decoded result, the callee call sequence with
arguments, and the deserializer state after the call (input position, peek
slot, depth). Cases cover every first byte with 45 tails and both flag values,
every valid peeked marker with five payloads, real and invalid UTF-8 names
through all string widths, and every container/ext marker at depths
0/1/2/3/0xfffe/0xffff with eight visitor knobs (Ok/Err, remaining 0/1/2/
0x10000/unchanged, depth written by the visitor).

Negative controls (`mutants.tsv`): 14 deliberately wrong models (e.g. restore
depth on visitor error, ignore the remaining count, carry len instead of the
consumed count, skip the value drop, skip depth restore after a mismatch,
invert the bin flag) and single-bit corruptions of the image at rule-steering
immediates and jump-table entries.

## Results and limitations

`summary.json` holds the machine-readable metrics (cases, case runs,
mismatches, result kinds, covered instructions per copy, mutant kill counts).


| metric | value |
|---|---|
| cases | 25,783 (77,349 case runs over 3 copies; 7,925 listed in `cases.tsv`) |
| mismatches | 0 |
| result kinds | callee_out 19,453; io 2,882; length_mismatch 1,653; callee_err 1,021; panic_sub 339; type_mismatch 161; depth 152; panic_add 76; utf8 46 |
| covered instructions | 504/531 per copy; residue 27 = 22 landing-pad instructions, 4 `jmp` after noreturn panic calls, 1 ud2 (`coverage.tsv`) |
| model mutants killed | 14/14 |
| image mutants killed | 69/70 |
| `any` helper | GOT 0x64e4198 -> RELATIVE 0x3475c70 in all copies |

The one surviving image mutant flips `mov cl,0x2` at 0x1b38a47. That value is
only read by the ext-table arm for tags 0xca..0xd3 (0x1b38dfb), and the marker
table sends those tags to the `any` arm, so no input reaches it: the mutant is
equivalent, not a missed rule.

Limitations: callee bodies are contract stubs, so the 40-byte Ok value and the
helper outputs are opaque tokens here; role names (visit_map, visit_str, ...)
are inferences from argument shapes and the sibling identifier-decoder packet.
Landing pads are not executed. No progress gate is requested.

Next question: which `Action` field visitors does the caller 0x2bd6140 pass
as the 32-byte visitor, i.e. what do visit_map 0x1fb1750 and visit_seq
0x1fb1d20 build into the 40-byte value?
