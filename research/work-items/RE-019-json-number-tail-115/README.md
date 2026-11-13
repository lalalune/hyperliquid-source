# RE-019: node #115 JSON number tail 0x3ef20f0 and type-mismatch peek 0x3ef2ab0 reconstructed

This packet shows that the part of the serde_json deserializer that the merged RE-019 reader stubs out is a small closed state machine, and it reimplements both bodies as pure functions that agree with the real machine code on 22,926 byte-derived cases. `0x3ef20f0` finishes a number after the digit run (u64 / i64 / f64 selection, the fraction loop with the `0x1999999999999998` accumulator limit, the e/E hand-off, and the f64 scaling by the 309-entry power-of-ten table plus a `1e308` pre-division). `0x3ef2ab0` is the value-type probe used for "invalid type" errors (byte dispatch through a 33-entry jump table, `false`/`true`/`null` literal matching, string and number sub-parses). With this a state loader can classify any JSON scalar and reproduce which error code, position fix-up and index state results.

- Component ID: storage (RE-019 state loader, JSON scalar path); task RE-009/RE-019 follow-up of the merged reader packet
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: repository head at the time of the run (clean worktree); no reference source is copied
- Claim status: observation (code bytes, constants, relocations, executed traces) with inference (role names). Equivalence is claimed only for the two bodies under the stated stubs, not for the whole node.
- Scope included: `0x3ef20f0..0x3ef2432` (834 bytes incl. int3 padding, 206 decoded rows) and its mid-function entry `0x3ef229b` (scaling tail); `0x3ef2ab0..0x3ef2db7` (192 decoded rows) with jump table `0x7beb94`. Excluded and stubbed at the call interface: exponent parser `0x3ef2820`, slow digit slot `0x64e1338`, error constructors `0x3ef1a90` / `0x3ef3450`, number parser `0x3ef2440` (merged RE-019 packet), position fix-up `0x4671240`, slots `0x64e0900` / `0x64e1350` / `0x64e08f8`, panic slots `0x64df520` / `0x64df848`.

## Reproduce

```
python3 tools/re19_json_number_tail_115.py --out research/work-items/RE-019-json-number-tail-115
python3 -m unittest tests.test_re19_json_number_tail_115
```

The tool checks the binary SHA-256 first, reads every code byte, constant, relocation and jump-table entry from the ELF with the repository parsers (`tools/elf_index.py`, `tools/fde_extents.py`), and runs the real bytes in a concrete x86-64 interpreter embedded in the tool. The binary is never executed. A run takes about 30 s; two runs give byte-identical output.

## Evidence

All addresses are #115 virtual addresses; offsets are file offsets resolved through section headers.

| File | Content |
| --- | --- |
| `constants.json` | scale constant `1e308` (`0x458ea0`), sign mask `0x8000000000000000` (`0x4559c0`), the two u64->f64 magic vectors (`0x451210`, `0x450170`), table slot `0x64e1330` -> table at `0x945558`, 309 entries, verified to be exactly `1e0..1e308` |
| `body.tsv`, `peek-body.tsv` | every decoded row of both bodies with an executed flag over the corpus |
| `cases-sample.tsv`, `finish-sample.tsv`, `peek-cases-sample.tsv` | the first 1,800 / 400 / 500 cases (input hex, index, accumulator, sign byte, result class, payload, final index, call sequence) |
| `kinds.tsv`, `peek-kinds.tsv` | outcome counts over all cases |
| `peek-jump-table.tsv` | the 33 rel32 entries: byte `0x5b..0x7b` -> block |
| `controls.tsv`, `equivalent-mutants.tsv`, `measure.json`, `summary.json` | negative controls, the one equivalent byte mutant, counts |

Observations (objdump of the bytes, excerpt):

```
3ef2108: jae 3ef2155            ; index >= len: no byte, integer result
3ef2113: cmp $0x2e,%eax ; je 3ef21b9   ; '.'   fraction loop
3ef211c: cmp $0x45,%eax ; 3ef2121: cmp $0x65,%eax   ; 'E' / 'e' -> call 0x3ef2820 with r8 = 0
3ef21ca: movabs $0x1999999999999998,%rbx   ; acc limit; acc == limit+1 allowed only for digit <= 5
3ef2220: add %rcx,%rcx ; lea (%rcx,%rcx,4),%rcx ; add %r15,%rcx ; jb 3ef2418 (panic, never executed)
3ef22c3: cmp $0x135,%ecx ; jb 3ef2308    ; |e| < 309 -> table lookup, else divide by 1e308 and retry
3ef2311: movsd (%r8,%rcx,8),%xmm1        ; table[|e|]  (r8 = *0x64e1330)
3ef2374: divsd %xmm1,%xmm0               ; e < 0: divide (no overflow check)
3ef231b: mulsd %xmm1,%xmm0 ; ... cmp 0x7ff0000000000000 ; je 3ef23e0 -> code 0xe via 0x3ef3450
3ef2ae7: lea .. # 7beb94 ; movslq (%rax,%rbx,4),%r11 ; jmp *%r11   ; bytes 0x5b..0x7b
```

Inferences (names, not strings): the output pair is `{0: f64 bits, 1: u64, 2: i64, 3: error}`; `dl` is "positive"; error codes 5 (EOF), 0xd (invalid number), 0xe (out of range), 9 (expected ident), 0xa (expected value).

## Implementation and comparison

`tail_model` / `finish_model` / `fraction_model` implement `0x3ef20f0` in plain Python (floats use IEEE doubles, the same arithmetic the SSE instructions perform); `peek_model` implements `0x3ef2ab0`. Findings:

- Negative numbers use the i64 result for magnitudes `1..2^63`; zero and larger magnitudes become f64 with the sign bit OR-ed in (so `-0` is `-0.0`).
- The accumulator stops at `0x1999999999999998`; one more digit is allowed only when acc is exactly `0x1999999999999999` and the digit is at most 5, otherwise the slow path `0x64e1338` is called with the negated digit count in r8 and the current position in r9.
- The decimal value is `float(acc)` followed by one division by a power of ten, so with at most 15 significant digits it equals the correctly rounded decimal parse (unit test against Python's own parser over 3,000 inputs), but with 16 or more it can differ in the last place (the model gives `9.098518033058475` for the text `9.098518033058477`).
- A fraction that ends right after `.` is error 5 at index+1; a non-digit directly after `.` is error 0xd; `e`/`E` after digits passes the negated digit count as scale.
- Scaling: while `|count| >= 0x135` the value is divided by `1e308` and the count moves by `0x134` toward zero (a zero value skips this); then one table division. The multiply branch with overflow check (code 0xe) needs a non-negative count, which the fraction path never passes (count = -(digits)); it was reached through the mid-function entry `0x3ef229b` with a hand-built frame, 4,000 cases.
- `0x3ef2ab0`: `[`->tag 0xa and `{`->tag 0xb are reported without consuming, `"` consumes the quote, zeroes the slot at de+0x10 and calls the string parser, `-` consumes and parses negative (flag 0), a digit parses positive (flag 1) without consuming; number parser tag 3 is returned as is, other tags go through slot `0x64e1350` and the position fix-up; everything else is error 0xa through `0x3ef1a90` then fix-up. Literal EOF/mismatch use `0x3ef3450` with codes 5 / 9 and skip the fix-up.

Comparison: for every case the interpreter runs the real bytes with the boundary callees replaced by deterministic hash stubs; result tag, payload, final index, de pointer/length, and the ordered call trace (name and arguments) must equal the model. Cases: 14,000 full-function (accumulator/limit, sign byte, truncation, junk), 4,000 mid-entry scaling cases, 4,926 peek cases (every first byte 0..255, every literal truncation and per-byte corruption, strings at many indices).

## Results and limitations

- 22,926 cases, 0 mismatches; 149 negative controls (26 + 18 model mutants, 105 byte mutants: inverted jcc/cmov, bumped immediates and 64-bit constants), 148 detected, 1 equivalent recorded in `equivalent-mutants.tsv` (low byte of the absolute-value mask `0x7fff..ff` at `0x3ef2326`, which only matters for NaN payloads that finite products cannot create).
- 202 of 206 tail rows execute; the four unexecuted rows are the two panic blocks (`0x3ef2418`, `0x3ef2425`: accumulate carry and digit-count decrement overflow), unreachable because of the `limit+1` guard and a 32-bit count. All 192 peek rows execute.
- Unresolved: behaviour of the stubbed callees (exponent parser, slow digit path, string parser, error object layout, position fix-up); the public serde_json error names; counts with absolute value near 2^31. The tail entry `0x3ef229b` is a test entry, not a call site in the binary.
- Interpreter tool (embedded) models only the instructions these bodies use and halts on anything else.
