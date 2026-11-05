# RE-021: reconstruct node #115 transaction admission before an address-09 call

This packet makes it possible to reconstruct, as executable code, how node #115 admits a transaction before any precompile (including address 09) can run: the environment validation `0x2b92c10` with every result tag and its order, the intrinsic/floor gas calculation `0x5be0720` with every located overflow panic, and the admission `0x2b93030` that combines them against the gas limit and the optional cap. A pure-Python reconstruction of all three functions agrees with the real instruction bytes on 9,500 cases, every instruction of the two outer functions runs, and 28 deliberately wrong models or patched code bytes are all detected.

- Component ID: `evm` (task RE-021, linked to RE-011)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`; no reference source is copied. The merged packet `RE-021-precompile-preflight-115` mapped these functions (table rows only); this packet proves them by evaluation.
- Claim status: observation for bytes, FDE extents, relocations, jump table and the evaluated input/output pairs; inference for field roles and EVM names; unresolved for live context values and the schedule actually installed at run time.
- Scope included and excluded: included are the three FDE bodies `0x2b92c10..0x2b93026`, `0x2b93030..0x2b931c1` and `0x5be0720..0x5be0a92`, the 5-entry jump table at `.rodata` `0x60735c`, and the GOT slots they call. Excluded are the panic helpers (stubs that stop the run), the schedule constructor, callers of `0x2b92c10`/`0x2b93030`, the payer balance helper and any Rust implementation.

## Reproduce

```
python3 tools/re21_tx_admission115.py --out research/work-items/RE-021-tx-admission-115
python3 -m unittest tests.test_re21_tx_admission115
```

Python 3 standard library only. The tool imports the shared `tools/elf_index.py` (sections) and `tools/fde_extents.py` (FDE extents), checks the input SHA-256 first, and never executes the binary or any external program. It decodes the real instruction bytes and runs them in a small concrete x86-64 evaluator (the decoder raises on any form outside its subset; GOT callees are resolved through `R_X86_64_RELATIVE` addends). Two generations with different `PYTHONHASHSEED` and `TZ` are byte-identical. A full generation takes about 2 minutes, the unittest about 3 minutes.

## Evidence

Coordinates are ELF virtual addresses. All numbers below come from the generated files.

| File | Content |
| --- | --- |
| `summary.json` | FDE extents, case counts, mismatches, outcome counts, instruction coverage, control counts |
| `constants.json` | jump table targets, relocated slots, panic location arguments, every `cmp` immediate with its VA, and the thresholds the case generator uses |
| `decoded-instructions.tsv` | linear decode of the three bodies (247 + 102 + 191 instructions), every byte accounted for, with an executed flag |
| `validate-cases.tsv` | 4,701 validation cases: context words, blob record first bytes, expected tag/payload, evaluated steps, result |
| `admit-cases.tsv` | 3,248 admission cases with the cost callee as a logging stub (argument contract) |
| `path-cases.tsv` | 1,551 cases of admission composed with the real cost body and a schedule object |
| `negative-controls.tsv` | 22 wrong models and 6 patched code bytes, each with its verdict |
| `unexecuted-instructions.tsv` | the 10 cost instructions no case reaches (see limits) |

Static facts read from bytes:

- Jump table `0x60735c` (`.rodata`, signed 32-bit offsets) sends type byte 0..4 to `0x2b92cea`, `0x2b92ce1`, `0x2b92de1`, `0x2b92e9e`, `0x2b92d65`; type 5 or more skips it.
- Thresholds: gas cap `or $0x1000000` at `0x2b92d3a` (with `sbb` mask: all ones below revision 13), initcode `add $0xc000` at `0x2b92f8d` plus `1 << 14` from revision 14 (`shl $0xe` at `0x2b92f8a`), floor gate `cmp $0xb` at `0x2b93127`.
- Slots: `0x64e6198 -> 0x5be0720` (cost), `0x64df520 -> 0x1681da0` (add overflow panic), `0x64df848 -> 0x1681e40` (sub overflow panic), `0x64df870` (mul overflow panic).

## Implementation and comparison

Python reconstruction (in the tool; functions `validate`, `cost`, `admit`, `path`), observed by evaluation:

Validation `0x2b92c10(out, ctx)`; `rev` is byte +`0x268`:

1. `rev > 8` and bit 0 of +`0xbc` clear: tag `0x21`, byte +8 = 0. `rev > 10` and words +0, +8 both zero: tag `0x21`, byte +8 = 1. Only these two write byte +8; success `0x25` writes only word 0.
2. +`0x260` set: if the 32-bit word +`0x100` is 1 and +`0x108 != +0x258`, tag `0x0c`; if it is not 1 and type is 1..4, tag `0x0d`.
3. +`0x265` clear: limit is +`0x248` if +`0x240` is set, else `0x1000000` for `rev >= 13`, else unlimited; gas +`0x1b8` above it gives `0x0e` with words (gas, limit).
4. Type dispatch. Let `X` = u128 +`0x130`, `Y` = u128 +`0xf0`, `M` = u64 +`0x98`, `b = (X >= M) | byte +0x264` (a byte OR, not a boolean), `t = (X < Y) & byte +0xe0`. Type 0, 1 (`rev <= 6`: `0x1a`): `b == 0` gives tag 1. Types 2 (`rev <= 7`: `0x1b`), 3 (needs the step-1 `rev > 10` latch: `0x1c`), 4 (`rev <= 11`: `0x1d`): unless `t == 0` and bit 0 of `b` is set, the tag is `t ? 0 : b*32 + 1`. With a non-canonical +`0x264` = 2 this yields tag `0x41` (30 cases). Type 4 then needs word +`0x1b0` nonzero (`0x19`). Type 3 then checks, when bit 0 of byte +0 is set, u128 +`0x160` >= u128 +`0x10` (`0x12`, payload both values), a nonzero count +`0x198` (`0x13`), byte 1 at the start of every 32-byte record at +`0x190` (`0x16`), and, when bit 0 of +`0x220` is set, count <= +`0x228` (`0x15`, payload max, count).
5. +`0x262` clear and gas +`0x1b8` > +`0x90`: tag 2.
6. `rev >= 10` and +`0x1dc` clear: initcode size +`0x120` against +`0x218` (if +`0x210`), else `2 * +0x208` (if +`0x200 == 1`; a negative signed value skips the check), else `0xc000` or `0x10000` from rev 14: larger gives `0x0b` with word 4 = limit.
7. Word +`0x1c0` all ones: tag 8; otherwise `0x25`.

Cost `0x5be0720(out, &schedule, data, len, create, accesses, keys, auths)`, schedule `S` = `*schedule`:

```text
tokens   = (len - zeros) * S[f0] + zeros
initial  = keys*S[118] + accesses*S[110] + tokens*S[f8] + S[120] + auths*S[e8]   (auth term = auths*(S[e8]+x) - auths*x, x = sat(S[158]+S[170]))
refund   = auths*x                                   (+ S[168] when create)
create:  initial += S[128] + sat(ceil(len/32) * S[130])
floor    = S[100]*ftok + S[108] + S[100]*sat(sat(20*accesses + 32*keys) * S[180])
ftok     = len*S[f0] if S[178] == S[f0] else tokens
out      = [initial, refund, 0, floor]
```

Every non-saturating step panics on overflow through a located helper; `path-cases.tsv` reaches 16 distinct (location, kind) pairs and the model predicts the same location argument and helper for each. Word 2 is always the constant 0 (`movq $0x0,0x10(%rdi)`).

Admission `0x2b93030(out, tx, rev, &schedule, floor_off, cap_on, cap)`: sums the 64-bit word +`0x10` of each `0x30`-byte access record (only when byte +`0x111` is set; overflow panics), calls the cost with data +`0x38`/+`0x40`, `create = (byte +0xfc == 0)`, the record count and sum, and +`0xd0`. Then `floor_off` clears the floor, a clear `cap_on` clears the refund word, `need = refund - word2 + initial` (both checked), and gas limit +`0xd8` gives tag 3 (need, limit) if `need > limit`, tag 4 (floor, limit) if `rev > 11` and `floor > limit`, tag 4 (`max(initial, floor)`, cap) if `cap_on`, `limit > cap` and that maximum exceeds `cap`; otherwise tag `0x21` with the four cost words. With the mode-13 schedule cited from `RE-021-precompile-preflight-115/schedule.json`, the 213-byte address-09 input (rounds 12, final 1) gives initial 21,876 and floor 23,190, and the evaluated code returns tag 3 at limit 21,875, tag 4 at 21,876 and 23,189, and `0x21` at 23,190 and 30,000 for revisions 12 and 13; revision 11 skips the floor check and returns `0x21` from 21,876 (rows `p0..p14`).

Comparison: `validate-cases.tsv` 4,701/4,701, `admit-cases.tsv` 3,248/3,248 and `path-cases.tsv` 1,551/1,551 match (tag, defined payload words, untouched words still holding the sentinel, callee arguments, panic location and helper kind; callee-saved registers and stack restored). Instruction coverage: validation 247/247, admission 102/102, cost 181/191. Negative controls: 28/28 detected (20 model variants such as `fee-cap-le`, `blob-max-ge`, `floor-from-rev11`, `cap-uses-floor-only`, `drop-auth-term`, `floor-always-tokens`; 8 one-byte code patches at `0x2b92c1c`, `0x2b92d18`, `0x2b92f8c`, `0x2b9312a`, `0x2b9315a`, `0x5be088a`, `0x5be08a0`, `0x5be0854`).

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler/linker settings, two-build comparison, normalization masks and whole-ELF equivalence: **not yet implemented or measured**.

## Results and limitations

- Payload words that the validation error path writes from scratch registers (for example word 1 of tags 1, 2, `0x0b`) are not compared; only the payloads named above are.
- 10 cost instructions are not executed: the `20*accesses` overflow branch needs about 2^60 access records, the zero-count add and the refund multiply/subtract panics are arithmetically unreachable (zeros <= len, `S[e8]+x >= x` under saturation). These are argued, not evaluated.
- The admission refund-underflow panic is reached only with the stub; with the real cost body word 2 is always 0, so in the composed path it needs `cap_on` clear and is unreachable. Live values of `rev`, `floor_off`, `cap_on`, `cap` and the installed schedule are not established.
- Only canonical 0/1 values are used for the admission `floor_off`/`cap_on` arguments.
- Field names (gas limit, base fee, blob fee, authorization count) are inferred from the arithmetic, not recovered.
- No gate change is requested; `evm` stays 0/4.

Next question: which caller binds `rev`, `floor_off`, `cap_on` and `cap` for the address-09 call frame, and does the payer balance helper `0x2973440` consume the `0x21` words unchanged?
