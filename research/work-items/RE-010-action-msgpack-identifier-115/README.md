# RE-010: MessagePack `Action` variant identifier decoder (rmp_serde marker dispatch) in node #115

This packet makes the MessagePack entry of `Action` deserialization reconstructable: given the
input bytes, an optional peeked marker, the recursion-depth budget and the caller flag, the pure
function `reconstructed_decode` in `tools/re010_action_msgpack_identifier_115.py` predicts exactly
what the three node #115 copies 0x1af3b70, 0x328bc70 and 0x48cccb0 return, which callee they call
with which arguments, and how they leave the deserializer (input cursor, peek slot, depth). The
tool proves this against the original bytes with an in-tool x86-64 subset interpreter on 25,202
cases per copy (75,606 runs, 0 mismatches). A Rust port can now write the `type` marker dispatch
of the MessagePack `Action` path (str/bin/map/array/ext/scalar arms, every EOF, depth, UTF-8 and
length-mismatch failure) from this packet instead of from disassembly.

- Component ID: `action-dispatch` (task RE-010)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: hyperliquid-source main `05bc2de303c05525b71e7e257426e741bc66a390`;
  no reference source was copied (rmp_serde names below are inferences checked against the bytes)
- Claim status: observation (byte-level behaviour of the three copies under the stated callee
  contracts) plus labelled inferences (rmp_serde/serde role names)
- Scope included and excluded: included are the three 1769-byte copies, their 225-entry marker
  jump table and 18-entry ext jump table, every normal-path arm and failure arm, and the callee
  argument contracts. Excluded are the callee bodies (the shared scalar helper 0x33fc5f0, the
  map/seq/ext visitors, the byte-sequence visitor, `core::str::from_utf8`), the `visit_str` and
  `visit_bytes` matchers themselves (reconstructed in sibling RE-010 packets), and the LSDA
  cleanup landing pads (not executed). No progress gate is requested.

## Reproduce

From the repository root (Python 3 standard library only, no external programs, the binary is
never executed):

```
python3 tools/re010_action_msgpack_identifier_115.py --out research/work-items/RE-010-action-msgpack-identifier-115
python3 -m unittest tests.test_re010_action_msgpack_identifier_115
```

The tool first checks the input SHA-256 and fails on any other binary. It writes `copies.tsv`,
`tables.tsv`, `insns.tsv`, `cases.tsv`, `coverage.tsv`, `mutants.tsv` and `summary.json`; all
are deterministic (no time, randomness, hash-order or absolute path in the output) and were
regenerated twice with different `PYTHONHASHSEED`/`TZ` and compared with `diff -r` (identical).
A full run takes about 3 minutes, most of it in the 35 image mutants.

## Evidence

Coordinates are virtual addresses of node #115; offsets in the TSV files are relative to each
copy's start. ELF sections come from `tools/elf_index.py` (SHT_NOBITS excluded from VA reads),
FDE extents and LSDA pointers from `tools/fde_extents.py` (`eh_frame_records`, `uleb`).

### Boundaries and copies (`copies.tsv`)

| copy | start | end (FDE) | bytes | insns | marker table | ext table |
| --- | --- | --- | --- | --- | --- | --- |
| C1 | 0x1af3b70 | 0x1af4259 | 1769 | 454 | 0x562094 | 0x562418 |
| C2 | 0x328bc70 | 0x328c359 | 1769 | 454 | see `copies.tsv` | see `copies.tsv` |
| C3 | 0x48cccb0 | 0x48cd399 | 1769 | 454 | see `copies.tsv` | see `copies.tsv` |

Every byte of each extent decodes into the fixed instruction subset (linear sweep ends exactly
at the FDE end). Zeroing only rel32/RIP disp32 fields, the three instruction streams are equal;
the jump tables map every tag to the same arm offset in all copies (`tables.tsv`, column
`same` = 1 on all 243 rows). Each copy has 8 direct callees in a fixed role order (map visitor,
seq visitor, visit_bytes, visit_str, error drop, ext visitor, byte-sequence visitor,
`_Unwind_Resume` checked through its `.rela.plt` JUMP_SLOT) and 5 GOT slots whose
R_X86_64_RELATIVE targets are checked: 0x64e3f30 -> 0x33fc5f0 (scalar helper), 0x64dfca8 ->
0x16815e0 (UTF-8 validation), 0x64df520 -> 0x1681da0 and 0x64df848 -> 0x1681e40 (overflow
panics), 0x64df4c0 -> 0x1680cab (cleanup terminate). The callers of the copies (C1 from 0x1fb1750
and 0x1fb1d20, C2 from 0x3952ed0 and 0x39535e0, C3 from 0x5687260 and 0x5687730) are listed for
orientation only and are not decoded here.

C1 visit_bytes/visit_str callees are 0x2b9cdb0/0x2ba1af0, C2 0x365d9d0/0x3662730, C3
0x4d63870 and its visit_str copy; these are the matchers reconstructed by the sibling
`action-type-matcher` and `action-variant-bytes` packets and are only stubbed here.

### Calling convention observed

`rdi` = 32-byte result, `rsi` = deserializer, `dl` = flag. Deserializer fields read or written:
+0x10 input pointer, +0x18 remaining length, +0x20 peeked marker tag (1 = none; the copy always
stores 1), +0x21 peeked payload, +0x22 u16 depth budget. The interpreter checks that no other
deserializer byte changes and that pointer + remaining always describes a suffix of the input.

### Marker dispatch (`tables.tsv`, `insns.tsv`)

A fresh marker byte `b` is classified before the table: `b < 0x80` -> tag 0 payload `b`
(positive fixint), `b >= 0xe0` -> tag 0xe0 payload `b` (negative fixint), 0x80..0x8f -> tag 0x80
payload `b & 0x0f` (fixmap), 0x90..0x9f -> tag 0x90 (fixarray), 0xa0..0xbf -> tag 0xa0 payload
`b & 0x1f` (fixstr), otherwise tag `b`. A peeked marker skips the read. The 225-entry table
(tags 0x00..0xe0) has 16 distinct arms plus `ud2`; the 188 tags that are not Marker values lead to `ud2`.
The 18-entry ext table (tags 0xc7..0xd8) is reached only for the ext tags; its 10 entries for
0xca..0xd3 lead to a TypeMismatch store that the marker table never routes to (dead entries).

| tags | arm | reconstructed behaviour |
| --- | --- | --- |
| 0x00, 0xe0, 0xc0, 0xc2, 0xc3, 0xca..0xd3 | 0x1af3c02/0x1af3c08 | call scalar helper(out, des, tag, payload) |
| 0xc1 | 0x1af3dc0 | Err TypeMismatch(Reserved) (word 0xc102) |
| 0xa0, 0xd9, 0xda, 0xdb | fixstr / str8/16/32 | length, bounds, `from_utf8`, then visit_str(out) or visit_bytes(tmp) fallback |
| 0xc4, 0xc5, 0xc6 | bin8/16/32 | length, bounds, then visit_bytes(out) when flag, else byte-sequence visitor(out, {ptr, end, 0}) |
| 0x80, 0xde, 0xdf | fixmap / map16/32 | depth check, map visitor, LengthMismatch(0) if Ok and len != 0 |
| 0x90, 0xdc, 0xdd | fixarray / array16/32 | same as map with the seq visitor |
| 0xd4..0xd8, 0xc7, 0xc8, 0xc9 | fixext1..16 / ext8/16/32 | depth check, ext visitor(tmp, {des, len u32, 0}), result copied |

Failure arms reconstructed (all compared against the bytes):

- Empty input with no peeked marker: Err tag 0 (marker read) with the static io error pointer
  0x641ccb0 (C1; per-copy value in `copies.tsv` via the same instruction index); cursor unchanged.
- Short 1-byte length (str8/bin8/ext8 with nothing left): Err tag 1 with the same static pointer,
  cursor unchanged. Short 2- or 4-byte length: the remaining bytes are consumed (cursor = end),
  then the same Err tag 1 (read_exact semantics).
- Payload longer than the rest: Err tag 1 with the bit-packed io error 0x2500000003
  (Simple(UnexpectedEof)); the length bytes stay consumed, the payload does not.
- Invalid UTF-8 in a str: the bytes go to visit_bytes into a stack temporary; if it returns Ok
  the variant index is returned; otherwise that error is dropped and Err tag 7 carries the
  Utf8Error (`valid_up_to` at +8, `error_len` Option at +0x10).
- Depth: budget 0 on entry -> subtraction overflow panic (0x64df848); budget reaching 0 after the
  decrement -> Err tag 8 (depth limit). On a map/seq visitor error the decremented depth is not
  restored; on Ok or LengthMismatch it is restored with an addition overflow check. The ext arm
  always restores from the value re-read after the visitor (a visitor that leaves 0xffff hits the
  addition overflow panic 0x64df520).
- Map/seq visitor Ok with a non-zero length: Err tag 4 LengthMismatch with u32 0 at +4.

## Implementation and comparison

The reconstruction is the Python function `reconstructed_decode(inp, peek, depth, flag, knob,
consts)`; no Rust implementation yet (not yet implemented). The comparison runs the original
bytes of each copy in a fixed-pattern x86-64 subset interpreter. Callees are contract stubs that
check their arguments (pointer roles, offsets into the input, lengths, ext header layout) and
write a per-callee 32-byte marker result; `knob` chooses Ok(0x2a) or Err(5) for the callees whose
result the copy inspects, and for the ext visitor an optional depth it leaves behind. Result,
call sequence and final deserializer state must all be equal.

Cases (`build_cases`): every first byte 0x00..0xff with 43 tails (every length width short,
exact and long, valid names and invalid UTF-8) and both flag values; every valid peeked tag with
5 payloads and 15 tails; every container and ext marker at depths 0, 1, 2, 3, 0xfffe, 0xffff with
4 callee knobs; invalid UTF-8 through all str widths; empty input. `cases.tsv` lists every 5th
case plus every case of a rare result kind; all cases are compared.

Negative controls (`mutants.tsv`): 11 deliberately wrong reconstructions (EOF tag, length EOF
error form, fixstr mask, depth limit, depth restore on error, LengthMismatch value, ext restore
source, str bounds, no visit_bytes fallback, inverted flag, Reserved as scalar) are each rejected
by at least one case; 35 single-bit corruptions of C1 (compare/mask/result immediates and 8
marker table entries; landing-pad bytes excluded) are each detected.

## Results and limitations

From `summary.json`:

- cases 25,202; runs 75,606; mismatches 0
- instructions covered 427/454 in every copy; the 27 uncovered instructions per copy are named
  in `coverage.tsv`: 20 in the LSDA landing-pad region, 1 `ud2`, 6 in the two map/seq
  depth-restore overflow panics (the map/seq visitor is not given the deserializer, so no callee
  contract can set the depth to 0xffff there)
- model mutants killed 11/11; image mutants killed 35/35

Limitations: callee bodies are stubs, so the result of the scalar helper, the visitors and the
byte-sequence visitor is only identified, not reconstructed. The flag in `dl` comes from the
caller and its meaning (which caller passes which value) is not established. Role names
(rmp_serde `deserialize_any`, serde field visitor, io error kinds) are inferences from layouts and
constants; the 0x2500000003 word matches the bit-packed `io::Error` Simple form with kind 0x25.
No gate is requested.

Next question: which callers (0x1fb1750 / 0x1fb1d20 and their twins) pass which flag value, and
does the scalar helper 0x33fc5f0 map positive fixints to variant indexes (visit_u64) for `Action`?
