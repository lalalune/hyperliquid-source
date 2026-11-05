# RE-010: variant payload dispatch after the two serde identifier decoders (node #115)

With this packet the step that follows variant identification can be rebuilt as
code: for every one of the 264 jump-table arms of the four `visit_enum` callers of
the identifier decoders 0x1c2d2c0 (18 tags) and 0x1bfca70 (114 short codes), a
one-line rule now gives the payload helper and its arguments, the Ok test on the
helper result, the enum discriminant written at `out+0`, the exact payload bytes
moved to `out+8...`, and the error path. The rule table (`SPEC` in the tool) is a
pure Python reconstruction, and the tool runs the original bytes over 9,712 cases
to show they match it.

- Component ID: `action-dispatch` (RE-010, transaction handler dispatch)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `05bc2de303c05525b71e7e257426e741bc66a390`;
  `references/can1357-hl` was not used (the enums here have no names in it that we could check)
- Claim status: observation (arm table, discriminants, call arguments, byte moves,
  all proved by running the original bytes against the reconstruction); inference
  (Rust/serde role names such as `visit_enum`, `newtype_variant`, `struct_variant`, niche)
- Scope included: the full bodies of the four functions 0x286c690, 0x286ac90,
  0x2870370 and 0x2871710 (FDE extents, 2,919 instructions, 186 conditional jumps).
  Scope excluded: the bodies of the payload helpers (92 distinct direct callees besides the
  identifier decoders, stubbed by contract), the identifier decoders (owned by the RE-010 enum-variant-matchers and
  msgpack-number packets), the u8 marker helper 0x3482410, and the names of the two enums.

## Reproduce

```
python3 tools/re010_variant_payload_dispatch_115.py --out research/work-items/RE-010-variant-payload-dispatch-115
python3 -m unittest tests.test_re010_variant_payload_dispatch_115
cd research/work-items/RE-010-variant-payload-dispatch-115 && sha256sum -c MANIFEST.sha256
```

Only the Python 3 standard library and the shared `tools/elf_index.py` and
`tools/fde_extents.py` parsers are used. No external program is called, and the
binary is never executed. The tool checks the input SHA-256 first, writes six
files (`functions.tsv arms.tsv cases.tsv coverage.tsv mutants.tsv summary.json`),
and exits non-zero if any case mismatches, any instruction is not covered, or any
mutant survives. A full run takes about 2 minutes, most of it the 131 image
mutants. Two runs with different `PYTHONHASHSEED`/`TZ` gave byte-identical output.

## Evidence

All addresses are virtual addresses in the `.text` of node #115. File offsets are
derived through the section headers, and NOBITS sections are excluded.

| fn | start | FDE size | frame | identifier | jump table | arms | Err disc |
| --- | --- | --- | --- | --- | --- | --- | --- |
| F18 | 0x286c690 | 831 | 0x28 | 0x1c2d2c0 | 0x5f8978 | 18 | 0x14 |
| F18R | 0x286ac90 | 1747 | 0x28 | 0x1c2d2c0 | 0x5f8898 | 18 | 0x14 |
| E114A | 0x2870370 | 5016 | 0xf8 | 0x1bfca70 | 0x5f8f88 | 114 | 0x86 |
| E114B | 0x2871710 | 5114 | 0xf0 | 0x1bfca70 | 0x5f9150 | 114 | 0x86 |

Facts read from the bytes (`functions.tsv`): the FDE extent, the `sub rsp` frame,
the first direct call (always the identifier decoder, called with `edx = 1`), the
`lea table(%rip); movsxd; add; jmp *` dispatch and its entries (each one is checked
to land on a decoded instruction start inside the function), every direct callee,
and the two GOT slots. 0x64df508 is `R_X86_64_GLOB_DAT memcpy`, and 0x64e2590 is
`R_X86_64_RELATIVE` -> 0x3482410.

A human-readable excerpt (objdump; not part of the generated evidence) of the
shared head of F18:

```
286c6a2: mov edx,0x1 ; call 1c2d2c0          # identifier -> [rsp+8]
286c6b6: cmp cl,0x9  ; je 286c702            # Ok niche tag 9, index in [rsp+9]
286c6bb..286c6f0: move [rsp+8..+0x28] -> out+8..+0x28 ; mov qword [rbx],0x14   # Err
286c707: lea rcx,[rip+..]  # 0x5f8978 ; movsxd rax,[rcx+rax*4] ; add ; jmp rax
```

### Rule grammar (`SPEC`, mirrored in `arms.tsv` with the arm VA)

`<fn> <variant> | <key> ; <calls> ; <out moves> | ...`. The rules are tried in
order and `*` is the fallback. A key `v/w` matches when the first `w` bytes of the
first helper result equal `v` (little-endian). `eof` is the inline-marker arm
with no byte to read. Calls are `helper~dst~rdx~ecx~r8~r9` (`va:` is a static
address, `v:` is an immediate, `-` means not set by the arm) or `memcpy~dst~src~len`.
`marker_u8~dst` is the GOT call with `edx/ecx` = the decomposed marker. Out moves
are `Dq` (qword discriminant at +0), `E` (Err discriminant + bytes 0..32 of the
failing result to +8), `X` (the helper wrote `out` itself), `Po=k.i+n` (copy n
bytes from offset i of call k's result to out+o, where k = 0 is the identifier
result), `Co=hex` (constant bytes), and `Ao=k.i*m+a` (qword at out+o = m * qword + a).

### What the table shows (counts from `arms.tsv`)

- **F18 / F18R are the same enum, read through two deserializer types.** Variant i
  of the 18 gets the same discriminant in both. The newtype variants use
  discriminant i+2 (0->2, 2->4, 4->6 ... 15->0x11), so 0 and 1 are the niche of
  the struct-like variants, which are deserialized straight into `out` (`X`). F18
  calls the generic helpers 0x18bf310 / 0x18bf220 / 0x18befa0, and the latter
  takes a field-name slice and a count (for example `va:643e308~9` = 9 fields).
  In F18R, 6 of the u8 newtype arms (variants 0, 4, 5, 6, 9, 10) are inlined:
  take the peeked marker if slot +0x20 is not 1, else read one input byte (the
  cursor at +0x10/+0x18 advances), split it as `decompose_marker` does (FixPos 0,
  FixMap 0x80 / FixArray 0x90 with `&0xf`, FixStr 0xa0 with `&0x1f`, 0xc0..0xdf
  kept as the byte, FixNeg 0xe0 with the raw byte), set +0x20 to 1, and call
  0x3482410(tmp, des, kind, data). With no input the result is
  `Err(InvalidMarkerRead(UnexpectedEof))`: tag 0 and the static 0x641ccb0, and the
  stale bytes 1..7 and 16..31 of the identifier result are copied along (`P9=0.1+7`, `P18=0.10+10`).
- **E114A / E114B are two enums over the same 114 codes.** E114A uses 13 generic
  helpers plus memcpy, and E114B uses 72 type-specific helpers plus memcpy. They
  agree on the discriminant of every newtype variant and on the Err discriminant
  0x86. The Ok tests found in the bytes are: tag byte 9 (51/55 arms), Result tag
  byte 0 (16 arms, Ok = 0, payload at +8), dword 2 / 4 / 0x14 (inner enum niches),
  qword `0x8000000000000000 | 0xd/0x15` (Vec/String capacity niche: Err when equal),
  and `i64::MIN` (detected by `cmp 0,[rsp]; jo`). Arm 109 has no branch:
  `disc = 5 * tag + 0x81` (`A0=1.0*5+81`), so Ok (tag 0) gives 0x81 and Err (tag 1)
  gives 0x86. Arms 77/84/87/94 move 0xa8, 0xb0 or 0xf0 bytes with memcpy. In arm 77
  the payload enum is niche-packed into the outer discriminant (`P0=1.0+f0`, no Dq).
- Duplicated arm bodies exist, for example E114A 25/26 and 65/66 (different VAs,
  identical rules). Swapping their table entries is an equivalent mutant, so the
  tool skips such pairs.

## Implementation and comparison

The reconstruction is `reconstructed()` + `SPEC` (264 lines) + `decompose_marker()`
in `tools/re010_variant_payload_dispatch_115.py`. A Rust implementation is not yet
implemented. The comparison is between the pure model and the original bytes,
interpreted by a fixed-pattern x86-64 subset decoder/interpreter (mov/movzx/movsxd/
lea/ALU/cmov/movups/jcc/call/ret plus `movabs`). Callee contract: each payload
helper writes a seeded SHA-256 byte stream into its destination (the stack slot up
to the frame top, or 0x100 bytes of `out`) with a chosen head value. memcpy is
executed. The identifier result is given by the case. The compared outcome is the
256-byte `out`, the full call list with arguments (destination, deserializer,
rdx/ecx/r8/r9 as static VA, immediate or unset), and the 40-byte deserializer
state after the call.

The head values ("knobs") are not chosen by hand: they are every immediate that a
function compares a helper result against (`cmp [rsp+d], imm`, `movabs`, and
`movabs|or`), plus qword 0/1 and a value that matches none of them.

Cases (`cases.tsv`, one row each with the out SHA-256 prefix): every arm x every
knob x 3 seeds, 22 identifier-error results per function (11 tags), and for the 6
inline marker arms of F18R all 256 input bytes, 19 peeked markers, empty input with
and without an explicit empty peek slot, and a slot marked empty with input present.

The SPEC lines were drafted by probing the interpreter and reading the listing, then
reduced to the smallest rule set that still matches. The tool proves the frozen text;
it does not re-derive it.

## Results and limitations

`summary.json`:

| fn | cases | mismatches | instructions covered | cond. jumps (taken / fall-through) |
| --- | --- | --- | --- | --- |
| F18 | 238 | 0 | 193/193 | 13 (13/13) |
| F18R | 1,906 | 0 | 454/454 | 49 (49/49) |
| E114A | 3,784 | 0 | 1,107/1,107 | 60 (60/60) |
| E114B | 3,784 | 0 | 1,165/1,165 | 64 (64/64) |

- Model mutants: 12/12 killed. 5 wrong behaviours (peek ignored, EOF keeps the
  peek slot, FixStr length masked with 0xf, Err discriminant +1, payload shifted
  by one byte) and 7 wrong SPEC lines (discriminant swap, struct field count, affine
  multiplier, dropped capacity-niche rule, memcpy length, Ok tag byte, EOF static pointer).
- Image mutants (`mutants.tsv`): one-bit flips of discriminant/compare/mask
  immediates and swaps of neighbouring jump table entries (equivalent pairs skipped).
  All were killed by cases, and none survived.
- Limits: payload helpers are contracts, not reconstructions, so their result
  layouts are known only as far as these four functions read them. The enum and
  variant names are not given here. The 114 codes are named by the
  enum-variant-matchers packet, but which code maps to which payload type is left
  for the helper bodies. No progress gate is requested.

Next question: what are the result layouts of the E114A generic helpers 0x18bf680
(Result tag byte, 40 bytes) and 0x18bfe80/0x18bf480 (`i64::MIN` niche), and do
they name the E114 payload types?
