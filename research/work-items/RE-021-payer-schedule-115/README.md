# RE-021: reconstruct node #115 gas schedule construction and the payer balance charge

This packet makes it possible to reconstruct, as executable code, two more steps of the node #115 transaction path that leads to an address-09 call: how the schedule constructor `0x5be2560` turns a mode byte into the 0x810-byte gas schedule object (all 256 modes, which fall into 10 distinct schedules), and how the payer balance helper `0x2973440` computes the required balance, the effective price, the per-blob auxiliary charge, its tag 6/7 rejections, the clamped remainder and its two panic exits. A pure-Python reconstruction agrees with the real instruction bytes on every mode, on 3,477 payer cases and on 2,048 cases that feed each evaluated schedule into the real cost body `0x5be0720`; 26 deliberately wrong models or patched code bytes are all detected.

- Component ID: `evm` (task RE-021, linked to RE-011)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`; no reference source is copied. The merged packet `RE-021-precompile-preflight-115` listed both functions (FDE rows, a mode-13 schedule read from immediates, and a prose payer table); this packet proves them by evaluating the code.
- Claim status: observation for bytes, FDE extents, relocations, constructor literals and the evaluated input/output pairs; inference for field roles (gas limit, fee caps, blob count) and Rust types; unresolved for the mode actually used at run time beyond the mode-13 selector already mapped, and for the live transaction values.
- Scope included and excluded: included are the FDE bodies `0x5be2560..0x5be29c7` and `0x2973440..0x29738de`, the GOT slots they call, and the cost body `0x5be0720..0x5be0a92` as a consumer of each constructed schedule. Excluded are the panic and allocation-error helpers (stubs that stop the run), the landing pads (unwinding is not evaluated), the once-initialization wrappers around the constructor, the callers of the payer helper and any Rust implementation.

## Reproduce

```
python3 tools/re21_payer_schedule115.py --out research/work-items/RE-021-payer-schedule-115
python3 -m unittest tests.test_re21_payer_schedule115
```

Python 3 standard library only. The tool imports the shared `tools/elf_index.py` (sections) and `tools/fde_extents.py` (FDE extents), checks the input SHA-256 first, and never executes the binary or any external program. It decodes the real instruction bytes and runs them in a small concrete x86-64 evaluator (the decoder raises on any form outside its subset). GOT callees resolve through `R_X86_64_RELATIVE` addends; the one `R_X86_64_GLOB_DAT` slot (`memset`) gets a synthetic per-symbol target and is named from `.dynsym`. Two generations with different `PYTHONHASHSEED` and `TZ` are byte-identical. A full generation takes about 80 seconds, the unittest about 1.5 minutes.

## Evidence

Coordinates are ELF virtual addresses. All numbers below come from the generated files.

| File | Content |
| --- | --- |
| `summary.json` | FDE extents, case counts, mismatches, outcome counts, instruction coverage, control counts |
| `constants.json` | every literal the constructor loads (instruction, rodata VA, words), every byte `cmp` immediate, relocated slots, the `expect` message read from bytes, panic locations |
| `decoded-instructions.tsv` | linear decode of the constructor and payer bodies (202 + 278 instructions), every byte accounted for, with an executed flag |
| `schedule-modes.tsv` | all 256 modes plus an allocation-failure run: model digest prefix, steps, result |
| `schedule-classes.tsv` | the 10 mode ranges with identical schedules and their nonzero header words |
| `compose-cases.tsv` | 2,048 cases: each mode's evaluated schedule fed to the real cost body with 8 inputs |
| `payer-cases.tsv` | 3,477 payer cases: inputs, expected outcome and value, steps, result |
| `negative-controls.tsv` | 14 wrong models and 12 patched code bytes, each with its verdict |
| `unexecuted-instructions.tsv` | the 14 constructor/payer instructions no case reaches (see limits) |

Static facts read from bytes:

- Constructor calls: allocation slot `0x64df480 -> 0x6355830` with size `0x810`, allocation error slot `0x64df490 -> 0x141e251` with (8, `0x810`), and `memset` (GLOB_DAT slot `0x64df750`) of `0x688` bytes from offset `0x188`.
- Mode thresholds (byte `cmp` immediates on `%bl` in `constants.json`): 2, 3, 6, 8, 10, 12, 13, plus `test %bl,%bl` for mode 0.
- Payer calls: the same allocation slot for two 32-byte boxes, the multiply-overflow panic `0x64df870 -> 0x1681dc0` with location `0x6443b50`, and `0x64df6a0 -> 0x1680c30` with message VA `0x6017c4`, length 73, error value 7, vtable `0x6443e58` and location `0x6441d20`. The message bytes read "effective balance is always smaller than max balance so it can't overflow".

## Implementation and comparison

Python reconstruction (in the tool; functions `schedule_words`, `payer`, `cost`), observed by evaluation.

Constructor `0x5be2560(mode)` returns a fresh `0x810`-byte object; bytes `0x188..0x810` are zero. Header words (offset: value), with `m` the low byte of `edi`:

```text
0x00 1   0x08 1   0x10 0   0x18 m>=3 ? 50 : 10   0x20 3   0x28 3   0x30 8   0x38 375
0x40 3   0x48 6   0x50 3   0x58 512   0x60 2   0x70 64   0x78 9000   0xc0 2300   0xf8 4   0x120 21000
0x128 (m==0 ? 0 : 32000; 9000 from m>=14)   0xd8 (m>=2 ? 25000 : 0; 0 from m>=14)
0xb0/0xb8 (15000, 24000) below 8, (4800, 0) from 8      0x130 m>=10 ? 2 : 0      0xf0 m<6 ? 17 : 4
0x68 32000, 9000 from 14     0xa0 and 0x138 hold the same 16-byte pair
```

The remaining pairs change at modes 6, 7, 12 and 14; `schedule-classes.tsv` lists every class. For example mode 13 gives `0xf0 = 0xf8 = 4`, `0x100 = 10`, `0x108 = 21000`, `0x110 = 2400`, `0x118 = 1900`, `0xe8 = 25000`, `0x178 = 1`, which reproduces the mode-13 schedule the merged preflight packet read from immediates; modes 14 and above set `0x100 = 16`, `0xe8 = 7500`, `0x158 = 0x2cd30`, `0x168 = 0x2cd30`, `0x170 = 0x8976`, `0x178 = 0x180 = 4`.

Payer helper `0x2973440(out, &mut B, tx, ctx)`; `G` = u64 tx+`0xd8`, `P` = u128 tx+`0x50`, `V` = u256 tx+`0x60`, `K` = byte tx+`0x111`:

```text
if G*P >= 2^128 or G*P + V >= 2^256:            tag 7
req = G*P + V
if K == 3:
    N = u64 tx+0xb8; if N >> 47: panic mul at 0x6443b50
    U = N << 17; req += min(2^128-1, U * u128 tx+0x80); if req >= 2^256: tag 7
if B < req:                                     tag 6, box(req), box(B)        (two 32-byte allocations)
eff = P
if K >= 2 and tx byte 0 bit 0: eff = min(P, min(2^128-1, u128 tx+0x10 + u64 ctx+0x98))
total = G*eff + V                                (cannot pass 2^128 for G*eff because eff <= P)
if K == 3: total += (ctx byte 0 bit 0) ? min(2^128-1, U * u128 ctx+0x10) : 0
if total >= 2^256:                              panic expect at 0x6441d20 (error 7)
charge = total - V
*B = (B - charge) mod 2^256
tag 0x21, out words 1..4 = max(0, B - charge)
```

Comparison: `schedule-modes.tsv` 257/257 (all modes byte for byte over `0x810` bytes, the allocation and `memset` arguments, plus the allocation-failure exit), `compose-cases.tsv` 2,048/2,048 (cost words or the panic location and kind), `payer-cases.tsv` 3,477/3,477 (tag; for `0x21` the four output words, the written balance and no allocation; for tag 6 both boxed values and an unchanged balance; for tag 7 an unchanged balance and untouched words 3..5; panic helper, location and the `expect` arguments; callee-saved registers and stack restored). Instruction coverage: constructor 202/202, payer 264/278. Negative controls: 26/26 detected (model variants such as `mode14-as-13`, `word18-from-2`, `cost-uses-mode13`, `aux-unsaturated`, `tag6-on-equal`, `effective-no-min`, `clamp-missing`; one-byte code patches at the mode compare immediates, the `K == 3` compare, the `N >> 47` shift count, the `K >= 2` compare, two branch opcodes and a box copy displacement).

Outcome counts: payer alloc_error 8, panic-mul 69, panic-unwrap 7, tag-0x21 1193, tag-0x6 1409, tag-0x7 791; composition panic-mul@0x64bf268 244, panic-mul@0x64bf2c8 498, return 1306.

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler/linker settings, two-build comparison, normalization masks and whole-ELF equivalence: **not yet implemented or measured**.

## Results and limitations

- The `expect` invariant (the effective total never exceeds the maximum total) holds only if the actual auxiliary price does not exceed its cap. The payer helper itself does not check that; the evaluated cases reach the `expect` panic and the zero clamp only with inconsistent inputs (ctx +`0x10` above tx +`0x80`). The validation packet's type-3 check `0x12` compares those quantities, but this packet does not prove that every caller runs it first.
- 14 payer instructions are not executed: the `jmp` after the second allocation-error call and the `ud2` after the `expect` call (both helpers stop the run), and the 12 landing-pad instructions that drop a box or a temporary and resume unwinding. Two branches execute but are never taken: the second `N >> 47` test (the first one already stopped such inputs) and the 128-bit overflow test of `G*eff` (unreachable because `eff <= P`). These are argued, not evaluated. The cost body is evaluated only as a consumer (156/191 instructions reached here; the earlier admission packet covers it).
- Words 1 and 2 of a tag-7 result hold scratch register values; they are not compared.
- Tag and field names (gas limit, max fee, value, blob count, blob gas per blob `2^17`, priority fee, base fee) are inferred from the arithmetic, not recovered. Header words `0x00` and `0x08` equal 1, consistent with reference counts, but that is an inference.
- The mode that a live node passes, and whether the once wrappers ever build more than the mode-13 schedule, are not established.
- No gate change is requested; `evm` stays 0/4.

Next question: which caller consumes the payer helper's `0x21` remainder and the mutated balance, and does it write the balance back to the account cache entry loaded by `0x4323870`?
