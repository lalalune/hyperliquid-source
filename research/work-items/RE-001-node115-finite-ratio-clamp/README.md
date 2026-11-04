# RE-001: node #115 finite ratio with a strict negative clamp

- Component: foundation arithmetic; first-party clearinghouse/vault caller association, not recovered source ownership.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference baseline: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New Python and evidence are independently authored under the repository MIT license; no inferred source copied.
- Bounded question: what does the complete leaf at `0x14ca350` return for finite, nonfinite, near-zero and overflow-producing numerator/divisor inputs?
- Status: instruction/byte observations and an all-input value rule under the stated floating-point environment; source name and domain units unresolved.
- Intended new files: this packet, `tools/node115_finite_ratio_clamp.py`, and `tests/test_node115_finite_ratio_clamp.py`. Task RE-001; no existing work item or milestone edit.

The leaf takes a numerator in XMM0.low64 and divisor in XMM1.low64. It returns RAX zero for either nonfinite input. With finite inputs, it clamps the numerator to positive zero exactly when it is strictly between negative epsilon and zero; a numerator at or below negative epsilon rejects. Signed zero is admitted without clamping. A divisor below positive epsilon rejects; equality is admitted. Otherwise DIVSD computes the quotient in XMM0.low64 and RAX is one exactly when that quotient is finite. Epsilon is the binary64 encoding `0x3cd203af9ee75616` (the rounded binary64 value of decimal `1e-15`, not the exact decimal rational). The model assumes nearest/even rounding, masked SSE exceptions and DAZ/FTZ disabled. This leaf neither sets nor proves that environment.

## Extent and closure

Original ELF virtual addresses are used throughout, with explicit file mappings in JSON. The window is `[0x14ca350, 0x14ca3e4)`, **148 bytes**, file offset `0x14c9350`. Body SHA-256: `c2f3b2eebf2e5723e5217cbfda7e5b463ab59c0d8c3c850b7af527b2ce8e4ff6`. The actual FDE is at VA/file offset `0xcae708` / `0xcae708` and refers to CIE `0xca6ed8`; LSDA is absent. Raw FDE/CIE records are in JSON. Following padding is `cccccccccccccccccccccccc`, **12 INT3 bytes**, ending at the next FDE start `0x14ca3f0`. Padding is excluded from the body hash.

The strict Python decoder consumes **38 instructions**, including **7 local branches** and **2 RET instructions**. Every instruction is reachable in the local CFG, every branch lands at an instruction start, and every path reaches a local RET. There are **0 callees**, no indirect dispatch, no stack frame, and no memory writes. Apart from RET's implicit return-address read, only the recorded read-only constants are loaded. Full body coverage and closed control flow support the function extent independently of treating an FDE as a function definition. No hot/cold helper or exceptional call is elided; floating-point traps remain subject to MXCSR. Valid instruction/constant mappings and an ordinary return-address stack are preconditions.

## Instruction walk and value proof

| VA | Bytes | Strict decode |
| --- | --- | --- |
| `0x14ca350` | `66480f7ec8` | `movq rax, xmm1` |
| `0x14ca355` | `66480f7ec2` | `movq rdx, xmm0` |
| `0x14ca35a` | `48b9ffffffffffffff7f` | `movabs rcx, 0x7fffffffffffffff` |
| `0x14ca364` | `4821ca` | `and rdx, rcx` |
| `0x14ca367` | `48beffffffffffffef7f` | `movabs rsi, 0x7fefffffffffffff` |
| `0x14ca371` | `4839f2` | `cmp rdx, rsi` |
| `0x14ca374` | `0f9fc2` | `setg dl` |
| `0x14ca377` | `4821c8` | `and rax, rcx` |
| `0x14ca37a` | `4839f0` | `cmp rax, rsi` |
| `0x14ca37d` | `0f9fc0` | `setg al` |
| `0x14ca380` | `08d0` | `or al, dl` |
| `0x14ca382` | `7403` | `je 0x14ca387` |
| `0x14ca384` | `31c0` | `xor eax, eax` |
| `0x14ca386` | `c3` | `ret ` |
| `0x14ca387` | `660f57d2` | `xorpd xmm2, xmm2` |
| `0x14ca38b` | `660f2ed0` | `ucomisd xmm2, xmm0` |
| `0x14ca38f` | `761e` | `jbe 0x14ca3af` |
| `0x14ca391` | `660f2e0507ecf8fe` | `ucomisd xmm0, [rip -> 0x458fa0]` |
| `0x14ca399` | `7614` | `jbe 0x14ca3af` |
| `0x14ca39b` | `660f57c0` | `xorpd xmm0, xmm0` |
| `0x14ca39f` | `f20f1015f9f7f8fe` | `movsd xmm2, [rip -> 0x459ba0]` |
| `0x14ca3a7` | `660f2ed1` | `ucomisd xmm2, xmm1` |
| `0x14ca3ab` | `77d7` | `ja 0x14ca384` |
| `0x14ca3ad` | `eb16` | `jmp 0x14ca3c5` |
| `0x14ca3af` | `31c0` | `xor eax, eax` |
| `0x14ca3b1` | `660f2ed0` | `ucomisd xmm2, xmm0` |
| `0x14ca3b5` | `77cf` | `ja 0x14ca386` |
| `0x14ca3b7` | `f20f1015e1f7f8fe` | `movsd xmm2, [rip -> 0x459ba0]` |
| `0x14ca3bf` | `660f2ed1` | `ucomisd xmm2, xmm1` |
| `0x14ca3c3` | `77c1` | `ja 0x14ca386` |
| `0x14ca3c5` | `f20f5ec1` | `divsd xmm0, xmm1` |
| `0x14ca3c9` | `66480f7ec2` | `movq rdx, xmm0` |
| `0x14ca3ce` | `4821ca` | `and rdx, rcx` |
| `0x14ca3d1` | `48b9000000000000f07f` | `movabs rcx, 0x7ff0000000000000` |
| `0x14ca3db` | `31c0` | `xor eax, eax` |
| `0x14ca3dd` | `4839ca` | `cmp rdx, rcx` |
| `0x14ca3e0` | `0f9cc0` | `setl al` |
| `0x14ca3e3` | `c3` | `ret ` |

MOVQ and AND first clear each input's sign bit in integer registers. Signed SETG against MAX_FINITE is valid here because the sign-cleared words are nonnegative signed integers; exponent-all-ones encodings reject before any floating-point comparison. The zeroed XMM2 then compares zero with the numerator. On the negative route, UCOMISD against the recorded negative epsilon and JBE exclude equality from the clamp. The clamped route explicitly zeroes XMM0. On the other route, the second zero comparison rejects remaining negative inputs. Both divisor checks compare positive epsilon with the divisor and use JA, admitting equality. Finally DIVSD, MOVQ, sign masking, and signed SETL against the infinity encoding accept every finite result, including signed zero and subnormals, and reject overflow to infinity.

On an early rejection, XMM0 retains the original numerator unless the negative clamp has already run; that case leaves positive zero. On quotient overflow, XMM0 holds the quotient infinity and RAX is zero. Signaling/quiet NaNs are rejected by integer operations with their input XMM0 bits preserved. The input nonfinite check precedes clamping. RAX is always zero-extended from EAX on return. Other volatile register values, flags and upper vector lanes are not a source ABI claim.

The JSON contains **2 constant objects** and **28 instruction-grounded boundary vectors**. The independent model uses exact integer rational division and explicit binary64 nearest/even rounding, including ties, underflow and overflow. It does not advance a captured PC or execute captured instructions. Tests separately freeze boundary expectations and compare the rational rounding helper with Python binary64 arithmetic on synthetic finite cases. These are static model checks, not a differential target run.

## Callers and source association

A full `.text` scan covers `[0x1419300, 0x63f0a00)`: each byte position at which an E8/E9 signed rel32 instruction fits is considered, including unaligned positions. It examined **800448 E8 positions** and **559515 E9 positions**, finding **0 direct caller/tail-transfer candidates** to the entry. This raw scan cannot identify indirect callers or prove instruction alignment; the empty result is stronger than omitting unaligned matches, but is not a reachability claim.

The retained R_X86_64_RELATIVE relocation at file offset `0x136b90` resolves slot `0x64e0058` to the leaf entry. A separate full `.text` FF15/FF25 RIP-relative scan found **3 slot reference sites** in **2 containing FDEs**. Each has a strictly decoded adjacent Location LEA and result-use witness. The witnesses and actual caller FDE/CIE records are retained; their entire caller bodies/CFGs are not semantically bound.

| Slot call site | Containing FDE range | Adjacent relocated Location |
| --- | --- | --- |
| `0x44807b9` | `0x447fe90..0x44810cf` | `l1/src/clearinghouse/clearinghouse.rs:1224:57` |
| `0x4480895` | `0x447fe90..0x44810cf` | `l1/src/clearinghouse/clearinghouse.rs:1270:57` |
| `0x44af279` | `0x44ae810..0x44af2e1` | `l1/src/vault/mod.rs:382:34` |

The clearinghouse witnesses test the low status bit and replace XMM0 with zero on failure; the vault witness compares RAX with one and branches on inequality. The Location argument is unused by this leaf. These data relocations prove a first-party call-context association, not the leaf's original symbol, defining module or financial interpretation. Register-indirect references, copied function pointers, vtables, other relocation types and dynamically modified slots are outside this census.

## Novelty before binding

At the baseline above, before creating this packet, these commands each exited with status one, empty stdout and empty stderr:

```sh
rg -i '14ca350' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '21799760' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'finite-ratio-clamp' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'finite_ratio_clamp' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The leaf is inside the assigned band and outside the supplied claimed-address list. There are no callee behaviors requiring a second novelty check. These are pre-write observations against local PR title lists, not a fresh remote search; rerunning against the completed packet naturally finds this packet. Before: no local packet bound the entry. After: the entire leaf, constants, closed CFG, boundary rule and caller associations are independently regenerable.

## Reproduce and validation scope

Working directory: repository root. Generation and verification require Python 3.10+ standard library and the authenticated ELF; neither imports nor invokes objdump. Discovery used GNU binutils 2.44 on Linux x86-64; final Python checks used Python 3.13.5. Generated records contain no machine-local paths or runtime state. The whole input digest is checked before parsing or creating output, using a read-only memory map. Existing ELF/FDE parsers are hash-pinned in the whitelist manifest. All recorded byte comparisons are exact; there are no normalization masks.

```sh
python3 tools/node115_finite_ratio_clamp.py --out research/work-items/RE-001-node115-finite-ratio-clamp/
python3 -m unittest tests.test_node115_finite_ratio_clamp -v
python3 research/work-items/RE-001-node115-finite-ratio-clamp/verify.py
make verify
make catalogue-check
```

Negative controls cover wrong digest and same-size window mutation at the public gate, unsupported/truncated instruction encodings, changed mask/branch/constant operands, shifted actual FDE bytes, a wrong relocation-backed callee target, caller displacement and padding corruption, and missing/extra/changed manifest files. README counts are rendered only from JSON and the tests compare the complete README with that rendering. Packet verification checks the exact manifest whitelist and regenerates JSON/README from the authenticated binary. Repository-wide tests and hosted CI are not claimed here; final command outcomes are recorded in the uncommitted submission report.

## Non-claims, limitations and next step

No native target or emulator was run; no network, signing, chain action, install or deployment occurred. No Rust reconstruction, source build, compiled-byte equivalence, recovered Rust Result/Option type, complete financial operation, panic behavior, runtime MXCSR state, whole-caller closure, whole-ELF equivalence or component gate is claimed. Code/data/helper/relocation closure is limited to the complete leaf and its constant loads; caller data/type provenance and exception-environment integration remain open. No inventory/literal analysis input or catalogue was modified or reinterpreted. All progress gates remain unchanged.

Next: trace numerator/divisor production and the result consumers in the retained first-party caller contexts, then establish their runtime floating-point environment before assigning units or integrating a Rust implementation.
