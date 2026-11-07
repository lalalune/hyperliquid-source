# evm: msgpack and pretty-JSON encoders of the (wei, user) record, with serde_json's key/escape/end helpers (node #115)

This packet reconstructs, as an executable Python model checked against the real bytes, every encoder node #115 has
for the two-field `(wei: U256, user: address)` record: the inline-`Vec<u8>` msgpack body and the rmp `Serializer`
msgpack body in both copy families, and the pretty-printing `serde_json` body together with the three
`PrettyFormatter` helpers it calls (object key writer, string escaper, end-object writer), which run for real. A
Rust port can now reproduce the exact bytes, reserve calls, error records, indentation state and panic of all three
encodings, including behaviours a clean serde derive would not show: the inline-Vec header byte is
`((flag ^ 1) << 4 | 0x82) & 0xff` (flag 2 writes `0xb2`, a fixstr marker; flag `0x11` writes a 2-entry map with no
names), the rmp-Serializer path opens a map for any non-zero flag but writes names only for flag 1, a failing JSON
value serializer returns its error with the serializer's `current_indent` still raised by one and `has_value` as it
was, and a `current_indent` of `u64::MAX` panics (add overflow) before a single byte is written.

- Component ID: `evm` (docs/COMPONENTS.md); no gate change requested.
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: lalalune/hyperliquid-source `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
  No reference source was used. Field names come from the binary's own texts (rip-relative `lea` targets read as
  bytes, and `mov` immediates); no Rust type name is claimed for the record (no adjacent type-name text exists).
- Claim status: observation for every table row and case result (bytes and tool output); inference for the Rust
  names (`SerializeStruct`, `PrettyFormatter`, `format_escaped_str_contents`, `RawVec::reserve`); unresolved items
  are listed below.
- Scope included: 5 FDE-bounded bodies and 3 helpers, all run REAL by the evaluator:

  | role | family a | family b | bytes | instructions | reached |
  |---|---|---|---|---|---|
  | wei_user_vec (record -> inline-Vec rmp) | `0x22eae20` | `0x38c1980` | 474 / 474 | 119 / 119 | 119 / 119 |
  | wei_user_ser (record -> rmp Serializer) | `0x22eacf0` | `0x38c1e50` | 301 / 301 | 80 / 80 | 80 / 80 |
  | wei_user_json (record -> serde_json pretty) | `0x22eab20` | - | 453 | 110 | 106 |
  | json_key_helper (`serialize_key`) | `0x26077c0` | - | 520 | 131 | 127 |
  | json_escape_helper (escaped str contents) | `0x25bf330` | - | 552 | 140 | 55 |
  | json_end_helper (`end_object`) | `0x232b070` | - | 311 | 87 | 84 |

  The three helpers are shared serde_json code. They are run as dependencies of the JSON body (their bytes decide
  its output) and their reached immediates are part of the byte-flip controls, but only their behaviour on this
  record's path is claimed.
- Scope excluded (recording contract stubs, see `stubs.tsv`): `RawVec::reserve` (`0x231e050` / `0x43bd910`), the
  rmp map/array header and str writers, the U256 and 20-byte value serializers of all three encodings
  (`0x29fe7f0`, `0x298c770`, `0x29fe6a0`, `0x298ac30`, JSON `0x29fed00`, `0x298b150` and the family-b copies),
  `memcpy` (import through GOT `0x64df508`) and the three panic entries (GOT `0x64df520` add overflow, `0x64df730`
  unreachable, `0x64df848` sub overflow). A family-c copy (`0x5af76d0` / `0x5af78b0`) and the callers are not
  covered (see Limits).

## Reproduce

From the repository root, with the node #115 binary at `artifacts/node/115/hl-node` (Python 3 standard library and
the shared `tools/fde_extents.py` / `tools/elf_index.py` parsers only; no binutils, no subprocess, the binary is
read, never executed):

```
python3 tools/evm_wei_user_record_115.py --out research/work-items/evm-wei-user-record-encoders-115
python3 -m unittest tests.test_evm_wei_user_record_115
```

The tool checks the input SHA-256 first and fails on any other binary. It regenerates every `.tsv`/`.json` file
here byte for byte (about one minute; two runs with `PYTHONHASHSEED`/`TZ` = default/UTC and 987/Asia/Seoul, PATH
without binutils, were compared with `diff -r`). `--scale 0.1` runs a 2,200-case subset for quick checks; the
committed files use the default scale 1.0.

## Evidence

All addresses are node #115 virtual addresses. The tool maps every VA to a file offset through the section headers
(`tools/elf_index.py`, skipping `SHT_NOBITS`) and takes body extents from `.eh_frame` FDEs (`tools/fde_extents.py`).

How the bodies were found: the pending L1ToEvmNativeTokenTransfer packet left the JSON serializer `0x22ea830` as its
next question. Its FDE neighbours `0x22eab20`, `0x22eacf0` and `0x22eae20` encode a second record with only the
keys `wei` and `user`: the same `wei` text `0x5ead56` and `user` text `0x459fa4`, the same value serializers. A
masked FDE comparison (call displacements and rip-relative operands blanked) finds same-shape copies
`0x38c1980` / `0x38c1e50` (family b, callers `0x41643a0`) and `0x5af76d0` / `0x5af78b0` (family c); the JSON body
has no copy. An ownership scan of the research tree and the open/merged PR file lists finds none of the five
bodies; the family-c Vec body `0x5af76d0` is named in an RE-001 caller list, so family c is left out.

### The record (fields.tsv)

| # | key | value | record offset | inline-Vec key | rmp-Serializer key | JSON key |
|---|---|---|---|---|---|---|
| 0 | wei | U256 by pointer | `+0x00` | fixstr `0xa3` + `movb 'i'` at +2 + `movw "we"` | str writer, text `0x5ead56` (b: `0x7a1405`) | `serialize_key`, text `0x5ead56` |
| 1 | user | 20 bytes by pointer | `+0x20` | fixstr `0xa4` + `movl "user"` | str writer, text `0x459fa4` | `serialize_key`, text `0x459fa4` |

### Flag rules (bodies.tsv `flag_tests`, `header_xor_shl_or`)

- wei_user_vec: header byte from `movzx ebp, [rdx+0x1b]; xor bpl, 1; shl bpl, 4; or bpl, 0x82`, then two
  `cmp byte [r14+0x1b], 1` (names only when the byte is exactly 1). Reserve rules (5 call sites): header and each
  fixstr marker reserve 1 only when `len == cap`; `wei` reserves 3 when `cap - len <= 2`, `user` reserves 4 when
  `cap - len <= 3`.
- wei_user_ser: `cmp byte [rdx+0xb], 0` chooses map (`!= 0`) or array (`== 0`), length 2; two
  `cmp byte [r14+0xb], 1` gate the names.
- wei_user_json: no flag. `current_indent` (`+0x18`) is tested for `u64::MAX` (`cmp $-1; je` panic, Location
  `0x642dc18`), incremented, `has_value` (`+0x20`) cleared, `{` pushed; for each field the key writer, `movw
  $0x203a` (`": "`), the value serializer and `movb $1, has_value`; finally `end_object(&indent, vec)` when the
  compound state byte is non-zero (always, after two keys).

Human-readable excerpt (objdump, not used by the tool):

```
22eae35: movzbl 0x1b(%rdx),%ebp
22eae3d: xor    $0x1,%bpl
22eae41: shl    $0x4,%bpl
22eae45: or     $0x82,%bpl            ; inline-Vec header
22eae74: movb   $0xa3,(%rax,%rsi,1)   ; fixstr 3
22eae8c: movb   $0x69,0x2(%rax,%rsi,1)
22eae91: movw   $0x6577,(%rax,%rsi,1) ; "we" + "i"
...
22eab29: mov    0x18(%rsi),%rax       ; JSON: current_indent
22eab2d: cmp    $0xffffffffffffffff,%rax
22eab31: je     22eacd8               ; add-overflow panic, Location 0x642dc18
22eab64: movw   $0x100,(%rsp)         ; compound = Map, state First
22eac31: cmpb   $0x0,0x1(%rsp)        ; state != Empty -> end_object
...
26077db: cmpb   $0x1,0x1(%rdi)        ; key writer: First -> "\n", else ",\n"
26078c6: movb   $0x2,0x1(%rax)        ; state = Rest
232b07b: mov    0x10(%rdi),%r13       ; end_object: current_indent - 1 (0 -> panic)
232b092: cmpb   $0x0,0x18(%rdi)       ; has_value -> "\n" + indent
232b134: movb   $0x7d,(%rax,%r14,1)   ; '}'
```

### Callees (callees.tsv, stubs.tsv)

Every direct call, tail jump, out-of-body conditional jump and GOT call of the 5 bodies and 3 helpers is listed
with its role. `check_static` re-derives from the bytes and asserts, for both families: the wei_user_vec call order
(U256, address) and its five reserve sites, the inline name immediates (`i`, `we`, `user`), the header arithmetic
(xor 1, shl 4, or `0x82`), the flag-test offsets and immediates, the wei_user_ser call order (map, array, str,
U256, str, address) and key texts; for the JSON body the call order (key, U256 JSON, key, address JSON, end), the
key texts, the panic `Location`, and the helpers' callees (the key writer calls the escaper once plus reserve; the
escaper and `end_object` only call reserve).

## Implementation and comparison

- Reconstruction: `tools/evm_wei_user_record_115.py`, `vec_marker`, class `Flow` (`record_vec`, `record_ser`,
  `inline_name`, `str_key`, `value`) and class `JsonFlow` (`record_json`, `byte`, `two`, `indent`, `escape`) - one
  model for both rmp families; only the callee addresses differ.
- Evaluator: a concrete x86-64 interpreter for the instruction forms of these bodies runs the original bytes (the
  same evaluator as the L1ToEvmNativeTokenTransfer packet; no instruction had to be added). Inputs are seeded
  regions: 4 record slots (`0x100` bytes of hash-stream bytes, one chosen per case), the inline Vec / rmp
  Serializer (`cap, ptr, len`, flag), the serde_json pretty Serializer (`&Vec`, indent pointer, indent length,
  `current_indent`, `has_value`), the indent text and the output buffer with a random prefix and capacity slack.
- Stubs record their arguments (slot, serializer, value pointer, key bytes) and answer from a per-case word plan;
  one call per failing case returns an error word, walking every error arm. `RawVec::reserve` must be called with
  `(vec, len, additional, 1, 1)` and grows capacity by `additional + extra`; `memcpy` copies; JSON value stubs
  return `rax` (0 = Ok, else a boxed error pointer).
- Compared per case: ordered call list (including every reserve with its length and size), every byte appended to
  the Vec and nothing past its length, final capacity and pointer, the 24-byte result record (rmp; only word 0 is
  written on success) or `rax` (JSON), the serializer bytes (rmp: unchanged; JSON: `current_indent` and
  `has_value` as modelled, everything else unchanged), the panic and its `Location`, callee-saved registers and
  stack, and that the records and the indent text are unchanged.
- Cases: 22,000 (wei_user_vec 4,000 x 2, wei_user_ser 4,000 x 2, wei_user_json 6,000), from a deterministic SHA-512
  stream; flags `0, 1, 2, 3, 0x10, 0x11, 0x21, 0x80, 0xfe, 0xff` and random bytes; tight capacities (`cap - len` 0..8)
  on every third case; prefixes up to 3,000 bytes; JSON indents `""`, `" "`, `"  "`, `"\t"`, `"\t\t"`, `"--"`,
  9 spaces and random 1..12-byte texts; `current_indent` 0, 1, 2, 3, 5, `u64::MAX - 1` (empty indent) and
  `u64::MAX`.
- Negative controls: 185, all detected (`controls.tsv`):
  - 29 wrong models (`model:*`): header-byte rule (map/array only, unmasked, length 6), reserve thresholds and
    missing reserves, names on any non-zero / odd flag, swapped value kinds, absolute or shifted record offsets,
    error records not wrapped / truncated, swapped fields, map only for flag 1, header length 6, header test on the
    low byte; JSON: no byte reserve, `": "` reserve threshold, one extra indent, indent before increment, escape
    always reserving, wrapping indent instead of the panic, newline instead of `",\n"`, `has_value` never set,
    `end_object` not lowering the indent, no closing newline;
  - 156 byte flips: one byte of every immediate operand of the 5 bodies and 3 helpers that the cases reach (flag
    tests, header xor/shift/or, fixstr markers, name bytes, spare-capacity tests, reserve sizes, value offsets,
    error words, `{`/`}`/`"`/`\n`/`": "`/`",\n"` bytes, compound state values, indent tests). `cmpb $0, state` is
    flipped to `$2` and `movb $2, state` to `$1` (bit 0 gives the same machine for every reachable state). Two
    immediates of the escaper's scan loop (start index `0x25bf34f`, end test `0x25bf364`) are excluded as
    equivalent mutants: with the escape-free keys `wei`/`user` the flush writes the same bytes whether the scan
    stops at or one byte past the key end (`EQUIVALENT_SITES`, counted in `summary.json`, asserted by the tests).
- Unit tests (`tests/test_evm_wei_user_record_115.py`, 38 tests): regeneration equals the committed files,
  manifest, scale, unreached rows explained, static facts, FDE sizes, key texts (family b's `wei` comes from a
  different pool), wrong digest, redirected callee, changed header constant, out-of-range start, `.bss` read
  rejected, hand-built cases for every finding (both families where they exist), mutants on hand cases, byte flips
  in a body and in the `": "` store, a corrupted result, and that the controls cover every body.

## Results and limitations

- 22,000 cases, 0 mismatches (first full run; the JSON helpers needed no evaluator change); 185/185 controls
  detected; 504 of 508 body instructions reached (helpers: 266 of 358, see below).
- Per body: every body has Ok and error results; the inline-Vec and JSON bodies call reserve (the rmp-Serializer
  bodies never do: their writers own the Vec); the rmp bodies have flag 1 / 0 / other cases;
  the JSON body reaches the indent-overflow panic (671 cases) (`summary.json` `per_body`).
- Findings:
  1. Inline-Vec header byte `((flag ^ 1) << 4 | 0x82) & 0xff` (both families): flag 0 -> `0x92` fixarray 2,
     1 -> `0x82` fixmap 2, 2 -> `0xb2` (a fixstr marker), `0x10` -> `0x92`, `0x11` -> `0x82` (a map without
     names), `0x80` -> `0x92` (the shift drops the high bit), `0xff` -> `0xe2`.
  2. Names only for flag == 1 in both rmp bodies; the rmp-Serializer path opens a map for any non-zero flag, so
     flag 2 gives a 2-entry map with no keys.
  3. rmp errors: a header or str-writer failure becomes `(0x8000000000000000, w0, w1)` (str writer: `rax`, `rdx`);
     a value-serializer failure is copied through as its three words; success writes only word 0
     (`0x8000000000000004`). Nothing is written to the Vec after a failure.
  4. JSON output for `current_indent = n`, indent text `I`, values `V0`, `V1` written by the value serializers:
     `{` `\n` `I*(n+1)` `"wei"` `: ` `V0` `,\n` `I*(n+1)` `"user"` `: ` `V1` `\n` `I*n` `}`; `current_indent`
     ends at `n`, `has_value` at 1.
  5. JSON errors: a failing value serializer returns its `rax` immediately; `current_indent` stays `n + 1`, no
     `}` is written, `has_value` stays 0 (first value) or 1 (second value). `current_indent == u64::MAX` panics
     before any write. `n = u64::MAX - 1` with an empty indent text completes (`end_object` sees `u64::MAX`).
  6. Reserve rules in the JSON path: single bytes reserve 1 only when `len == cap`; `": "` and `",\n"` reserve 2
     when `cap - len <= 1`; each indent copy reserves `len(I)` when `len(I) > cap - len`; the escaped key flushes
     with reserve `len(key)` when `len(key) > cap - len`.
- Unreached (`unreached.tsv`): in the JSON body, the `unreachable!()` arm after the key writer (compound state 0 is
  always Map) - 4 instructions; in the key writer the same `unreachable!()` panic - 4; in `end_object` the
  `current_indent == 0` panic - 3 (the body always incremented it first); in the escaper, the escape arms - 85
  (the keys hold no byte whose ESCAPE entry is non-zero). The escaper's own escaping is therefore not claimed.
- Limits: the value serializers (U256 decimal/hex text, address hex) and rmp writers are stubs; their encodings are
  not claimed. Family c (`0x5af76d0` / `0x5af78b0`) and the callers (`0x2264c90`, `0x41643a0`, JSON `0x25aac50`)
  are not covered (`0x2264c90` is named in RE-001 caller lists). No progress gate is requested.
- Observation data: `cases-sample.tsv` keeps every 7th case of each body; all 22,000 results are covered by
  `all_cases_sha256` in `summary.json`, which the tool recomputes.

Next question: reconstruct the JSON value serializers of this record (`0x29fed00`, U256 through `core::fmt::write`
into a 256-byte stack buffer, then quoted; `0x298b150`, address hex) and the escaper's escape arms with direct
cases, then the sequence callers `0x41643a0` / `0x25aac50` that hold slices of this record.
