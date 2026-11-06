# RE-010: MessagePack numeric variant identifier path (number dispatcher + visitors) in node #115

This packet makes the numeric branch of MessagePack enum-tag decoding reconstructable: given the
marker byte, the marker's data byte and the input bytes, the pure function `reconstructed` in
`tools/re010_action_msgpack_number_identifier_115.py` predicts exactly what node #115 returns when
a variant identifier (including the `Action` tag, N = 92) arrives as nil, bool, an integer or a
float: the variant index for an in-range unsigned integer, `invalid_value(Unsigned(v), "variant
index 0 <= i < N")` out of range, `invalid_type(Unit | Bool | Signed | Float)` with the exact
payload bits otherwise, the static `UnexpectedEof` error on a short payload, and the input cursor
afterwards. The tool proves this by interpreting the original bytes of five 653-byte dispatcher
copies and all 45 of their callees (2,770 instructions, 100% executed) on 8,579 cases with
0 mismatches. A Rust port can now write the integer form of the `Action` tag (and of four other
enum identifiers with 16, 18, 79 and 114 variants) from this packet instead of from disassembly.

- Component ID: `action-dispatch` (task RE-010)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: hyperliquid-source main `05bc2de303c05525b71e7e257426e741bc66a390`;
  no reference source was copied (rmp_serde / serde role names below are inferences that the case
  comparison checks)
- Claim status: observation (byte-level behaviour of the five dispatcher copies and their callees
  under the stated formatter contract) plus labelled inferences (role names, which enum each
  copy serves)
- Scope included and excluded: included are the five dispatcher copies 0x14b7dc0, 0x33fc5f0,
  0x3408270, 0x3408ab0, 0x3486dd0, their shared 33-entry marker jump table shape, each copy's nine
  callees (`visit_u64` with its integer -> variant jump table and range error, `visit_i8/i16/i32/
  i64`, `visit_f32/f64`, `visit_bool`, `visit_unit`), every EOF arm and the non-scalar
  pass-through. Excluded are the shared error formatter each callee calls (0x3046740, and
  0x14a9620 for N1; treated as a contract stub whose arguments are checked), the callers that
  reach the dispatchers through their GOT slots (the `Action` identifier decoders and four
  sibling decoders), and which named enum the N1/N3/N4/N5 copies serve. No progress gate is
  requested.

## Reproduce

From the repository root (Python 3 standard library only, no external programs, the binary is
never executed):

```
python3 tools/re010_action_msgpack_number_identifier_115.py --out research/work-items/RE-010-action-msgpack-number-identifier-115
python3 -m unittest tests.test_re010_action_msgpack_number_identifier_115
```

The tool checks the input SHA-256 first and fails on any other binary. It writes `copies.tsv`,
`tables.tsv`, `constants.tsv`, `insns.tsv`, `cases.tsv`, `coverage.tsv`, `mutants.tsv` and
`summary.json`. Output is deterministic (no time, randomness, hash-ordered iteration or absolute
paths); two runs with different `PYTHONHASHSEED` and `TZ` gave byte-identical folders. A run
takes about 70 s. Every number below comes from those files. ELF sections come from
`tools/elf_index.py` (NOBITS sections excluded from VA reads) and FDE extents from
`tools/fde_extents.py`.

## Evidence

Coordinates are virtual addresses in node #115; file offsets are derived from section headers.

**Five dispatcher copies** (`copies.tsv`). Each starts an FDE that is exactly 653 bytes long and
is the `R_X86_64_RELATIVE` target of one GOT slot. The tool scans `.text` for `ff 15 rel32` calls
through each slot:

| copy | dispatcher | GOT slot | slot call sites (in FDE) | `visit_u64` | N |
|------|-----------|----------|--------------------------|-------------|---|
| N1 | 0x14b7dc0 | 0x64dff80 | 0x14b3122 (in 0x14b3080) | 0x14c1cb0 | 79 |
| N2 | 0x33fc5f0 | 0x64e3f30 | 0x1af3c12, 0x328bd12, 0x48ccd52 (in 0x1af3b70, 0x328bc70, 0x48cccb0) | 0x3663820 | 92 |
| N3 | 0x3408270 | 0x64e2ef0 | 0x195c1e2, 0x30982f2, 0x4a3c4f2 | 0x444fd10 | 16 |
| N4 | 0x3408ab0 | 0x64e4998 | 0x1bfcb12, 0x31490f2, 0x48e7a12 | 0x4690720 | 114 |
| N5 | 0x3486dd0 | 0x64e4b20 | 0x1c2d362, 0x3343a22, 0x49d11e2 | 0x4683380 | 18 |

All five decode to the same 197 instructions; after zeroing rel32/disp32 fields the byte shapes
are identical, and the marker jump tables give the same arm offsets. The N2 slot is called from
inside the three 1769-byte MessagePack `Action` identifier decoders, so N2 is the copy behind
the `Action` tag; N = 92 matches the 92-variant `Action` enum.

Human-readable start of N2 (objdump excerpt, not used by the tool):

```
33fc5f1: movzx  r8d,dl              ; marker
33fc5f5: lea    eax,[r8-0xc0]
33fc5fc: cmp    eax,0x20
33fc5ff: ja     33fc648             ; not 0xc0..0xe0: FixPos or pass-through
33fc601: lea    r8,[rip+...]        ; 0x7745a4, 33 x i32 table
33fc608: movsxd rax,DWORD PTR [r8+rax*4]
```

**Marker table** (`tables.tsv`, `marker_arm` rows; role = callee the arm enters with an 8-byte
payload, found by running it):

| marker | payload read | callee | result |
|--------|--------------|--------|--------|
| 0x00 (FixPos, value in data byte) | none | `visit_u64` | index or range error |
| 0xc0 nil | none | `visit_unit` | `invalid_type(Unit)` |
| 0xc2 / 0xc3 | none | `visit_bool` | `invalid_type(Bool(false/true))` |
| 0xca f32 | 4 bytes BE | `visit_f32` | `invalid_type(Float(cvtss2sd(x)))` |
| 0xcb f64 | 8 bytes BE | `visit_f64` | `invalid_type(Float(x))` |
| 0xcc / 0xcd / 0xce / 0xcf | 1 / 2 / 4 / 8 bytes BE | `visit_u64` | index or range error |
| 0xd0 / 0xd1 / 0xd2 / 0xd3 | 1 / 2 / 4 / 8 bytes BE | `visit_i8/16/32/64` | `invalid_type(Signed(sign-extended))` |
| 0xe0 (FixNeg, value in data byte) | none | `visit_i8` | `invalid_type(Signed(data as i8))` |
| 0xc1, 0xc4..0xc9, 0xd4..0xdf, any other marker | none | none | tag 2 + marker + data byte (pass-through) |

**Failure arms.** A payload shorter than its width moves the cursor to the end of the input
(ptr += len, len = 0) and returns tag 1 with the static error at 0x64622f0 (N2..N5) / 0x63f8470
(N1): `io::Error` kind byte 37, message "failed to fill whole buffer" (`constants.tsv`). In N2
the f32, f64 and u16 arms share the tail at 0x33fc72a, the other multi-byte arms the tail at
0x33fc7db, and the 1-byte arms test for an empty input and jump straight to the error store;
all of them are executed.

**`visit_u64`** (`tables.tsv`, `u64_index` rows): `cmp rsi, N-1; ja error`, then an N-entry jump
table whose arms are each `movw $((i<<8)|9), (%rax); ret`. The tool reads every arm: in all five
copies arm i stores index i (identity). Out of range it builds `Unexpected::Unsigned(v)` (tag 1)
and an `&str` expected value whose text the tool reads through a RELATIVE relocation:
`variant index 0 <= i < N` for N = 79, 92, 16, 114, 18; message pieces at 0x446a6b
("invalid value: ").

**Small visitors.** Each writes a `serde::de::Unexpected` on its stack (tag byte at +0x38:
0 Bool, 2 Signed, 3 Float, 7 Unit; payload at +0x39 for Bool, +0x40 for the others) and calls
the formatter with message pieces 0x44f07a ("invalid type: ") and the visitor itself as the
expected value. `visit_i8` uses `movsx rax, sil`; `visit_f32` widens with `cvtss2sd`, which
quiets a signalling NaN (case `7f800001` gives `0x7ff8000020000000`).

## Implementation and comparison

Not yet implemented in Rust. The executable reconstruction is the pure Python function
`reconstructed(marker, data, inp, n_variants, eof_ptr)` plus `visit_u64` and `f32_to_f64_bits`
in the tool (about 60 lines); the target-grounded comparison is:

- **Interpreter.** A fixed-pattern x86-64 subset decoder sweeps every FDE byte of the dispatcher
  and its nine callees (any unknown encoding is a fault, not a skip). An interpreter runs the
  original bytes with `rdi = out`, `rsi = deserializer` (input pointer at +0x10, length at
  +0x18), `dl = marker`, `cl = data`; the upper bits of rdx/rcx carry junk to show only the low
  bytes are read. Callees run for real through a modelled return stack. Only the formatter is a
  stub: it checks its arguments (message pieces, Unexpected tag and payload, expected value is
  either the `variant index` text or the visitor) and writes a 32-byte mark that must reach
  `out` unchanged.
- **Cases** (`cases.tsv`, one row per copy and case): all 256 data bytes for FixPos and FixNeg,
  three data bytes plus an input-carrying row for every non-scalar marker, every unsigned value
  0..N+2 for u8 and boundary values for wider widths, signed and float specials (signed zero,
  infinities, quiet and signalling NaN, subnormals), every short payload length, and a trailing
  byte that must stay unread. 1,731 / 1,744 / 1,668 / 1,766 / 1,670 cases for N1..N5.
- **Comparison.** Result tuple and consumed input length must equal `reconstructed` exactly, and
  the deserializer bytes outside ptr/len must be unchanged.

## Results and limitations

`summary.json`:

- 8,579 / 8,579 cases match (0 mismatches) across the five copies.
- Instruction coverage: 2,770 / 2,770 decoded instructions executed (`coverage.tsv`: dispatcher
  197 per copy; `visit_u64` 194 / 220 / 64 / 264 / 68; small visitors 23-25 each).
- Wrong reconstructions are rejected: 18 / 18 model mutants (u8 and i8 swapped, FixNeg treated
  as pass-through, pass-through drops the data byte, EOF keeps the cursor, little-endian
  payload, bound off by one, signed payload zero-extended, f32 bits not widened, reversed index
  table), each run on N1 and N2 (`mutants.tsv`).
- Corrupted images are rejected: 34 / 34 single-site byte mutants on N1 and N2. 26 change at
  least one case outcome; 8 are refused before any case runs, because the static checks no longer
  hold (a `visit_u64` bound + 1 makes word N of the table a non-arm, `ja` -> `jae` breaks the
  `cmp`/`ja` opening check, and NOP-filled `bswap`/`cvtss2sd` bytes fall outside the decoded
  subset). The mutants are (range `ja` -> `jae`, range constant 0x20 -> 0x1f, FixPos `jne` -> `je`,
  `visit_u64` bound + 1 and `ja` -> `jae`, dropped `bswap`, `rol` by 0, Unexpected tags changed in
  four visitors, `movsx` -> `movzx`, EOF tag and pass-through tag changed, `cvtss2sd` removed,
  u8/i8 marker table entries swapped, index table entries 1/2 swapped).

Limitations: the formatter (0x3046740) is a stub, so the rendered error string is not proven,
only its inputs. Which enum the N1, N3, N4 and N5 copies decode is not named; only N and the
call-site functions are recorded. The dispatcher's callers are listed but not interpreted here
(the N2 callers are the `Action` identifier decoders). Behaviour is shown for the inputs listed
in `cases.tsv`; the integer paths are covered at every in-range value for u8 and at the
boundaries for wider widths. No progress gate is requested.

Next question: which serde enums do the N1 (79 variants), N3 (16), N4 (114) and N5 (18)
dispatchers serve? Their slot call sites sit in the decoders 0x14b3080, 0x195c140, 0x1bfca70 and
0x1c2d2c0, whose `visit_str` matchers would name the variants.
