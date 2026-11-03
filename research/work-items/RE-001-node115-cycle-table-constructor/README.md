# RE-001: node115 cycle-table constructor, raw bounds and packed return

- Task/component: RE-001 / `foundation`, one bounded static constructor question.
- Sole target: node **#115**, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Included: actual FDE `[0x1628dd0,0x1628f50)`, **384 bytes / 103 native instruction rows**, the 400 accessed bytes at `0x46be3b`, all selected branch/call operands and two error-call slot bindings.
- Excluded: callers, source input/calendar types, opaque error helpers, runtime behavior and Rust implementation. No acceptance gate changes.

## Requirement, selection and target identity

The active scope requires new #115 function-map evidence. This packet resolves how one raw i32/u32/u8 constructor derives a bounded table index, chooses a 52/53 limit, adjusts a signed coordinate and packs a result. The complete 280-open-PR inventory in `work/fifth-live-prs.json` had no exact-address/scope match for `1628dd0`, its cycle-table construction or the selected input/output protocol. Current retained research, source and tool searches found no packet for this body/table. Screening is not a claim of ownership; recheck live work before submission.

Historical machine-code patterns supplied only a search lead. Every address, body, table, operand, FDE and relocation below was freshly recovered from the authenticated #115 artifact. In particular this body has **no table-byte>=32 branch**; no retired-release guard or error arm is inherited. No unlicensed inferred implementation or source labels were consulted or copied. New analysis/code is independently authored; captured bytes retain upstream rights.

Before: the retained #115 tree has no grounded packet for this constructor. After: one full FDE, a complete table-access population and explicit integer identities ground its numeric paths and unresolved boundaries. This is static research, not a completed component or a release-label-only migration.

## Reproduce and review status

Observed: macOS 26.4.1 (25E253), CPython 3.11.15, Apple LLVM objdump 21.0.0. From repository root with the authentic #115 LFS input:

```sh
python3.11 -B research/work-items/RE-001-node115-cycle-table-constructor/verify.py --negative-controls
python3.11 -B research/work-items/RE-001-node115-cycle-table-constructor/arithmetic-check.py
python3.11 -B research/work-items/RE-001-node115-cycle-table-constructor/capture.py --output work/node115-cycle-recapture
```

The capture directory must be new. Another host can pass `--objdump /installed/path/llvm-objdump`. The producer authenticates the full input **before** creating a private byte-identical temporary snapshot under ignored `work/`; LLVM reads that snapshot, not a later mutable checkout path. Only snapshot path labels are replaced with the repository-relative artifact label. Original instruction/data bytes are unnormalized. No captured program, instruction evaluator, network request, chain action, compiler or model call runs.

`capture.py` preserves the exact selected `-d` range and `--dwarf=frames` recipe. Compare its `body.objdump.txt`, `frames.txt` and `evidence.json` with the packet. A second collection reproduced all three exactly; `arithmetic.json` also regenerates exactly. `verification.json` retains the structural and corruption results. The generic ELF verifier is adapted from the author's independently authored evidence tooling and freshly validated against #115.

**This is a reviewable DRAFT. The required repository full suite has not run under the current authorization and its gate remains unmet.** The integrating operator records the allowed static subset separately; it is not a full-suite substitute. A maintainer must arrange compliant remaining validation before marking the PR ready. No workflow/test configuration is changed to avoid that requirement.

## Actual FDE, coordinates and data

All coordinates are linked **ELF VAs** with half-open ranges and section-resolved file offsets. FDE `.eh_frame+0x17f10` decodes under the observed `zR`, pcrel-sdata4 CIE to `[0x1628dd0,0x1628f50)`, independently agreeing with LLVM frame output. Every body byte is decoded once; unwind-table spacing and nearest-symbol labels are not substituted for the actual range or function identity.

The table load at `0x1628e05` uses base `0x46be3b` and a byte-sized entry. All 400 accessed bytes are retained, not guessed from historical data. Their values are in `{1,2,3,4,5,6,7,9,10,11,12,13,14,15}`. This is a raw table observation, not a source enum/calendar guarantee. There is no local >=32 guard before the target's register BT; x86 register BT uses the low five index bits. The actual retained bytes are below 32 anyway.

The two unique `R_X86_64_RELATIVE` bindings are `0x64df848 -> 0x1681e40` and `0x64df520 -> 0x1681da0`. Their native RIP-displacements, original relocation entries and target addresses are retained. The associated constant-pointer arguments are `0x6405450` and `0x6405438`. Neither helper's source identity or return/exception behavior is closed.

## Entry fields and exact index identity

Let Y be signed low32 of entry EDI, W be low32 of entry RSI, and D be low8 of entry RDX. These are numeric register inputs only; year/week/weekday names are not established.

For Y, the code multiplies its sign-extended value by `C=0x51eb851f`, shifts the signed product right 39, and adds its sign bit. This produces truncation-toward-zero division by 400. It subtracts 400 times that quotient, then adds 400 exactly when the remainder is negative. Consequently the table index is the Euclidean residue **Y mod 400 in 0..399**.

The all-i32 arithmetic proof is explicit in `arithmetic.json`: `400*C = 2^39 + 112` and `112*2^31 < 2^39`. The positive quotient error is therefore strictly below one residue step `1/400`; it cannot cross an integer boundary. For negative nonzero inputs, signed floor plus one gives truncation toward zero. Products fit i64 across all i32 Y. The Euclidean correction then establishes the complete index bound. **2,805** retained finite identities supplement this argument; they are not mislabeled as exhaustive i32 execution. The same derivation applies after either checked ±1 adjustment.

For F = the loaded table byte, the code computes `L=52+bit(0x406,F&31)`, then returns the initialized EAX zero when `(W-1) mod 2^32 >= L` unsigned. Thus the local admitted second-input range is 1..L, with L 52 or 53 for the retained table. No source validity or reachable-input population is assigned.

## Coordinate/ordinal-like adjustment

For the admitted second word, the next numeric value is `S = low8(D) + 7*W` modulo 2^32. Here W<=53 and D<=255 bound S to at most 626 without overflow. Define `O=(F&7)` when that value is at least 3, otherwise `(F&7)+7`. The table observations give O in 3..9.

The exact branch families are:

- If S<=O unsigned, the code decrements Y under an overflow check. It loads the neighboring-coordinate table byte F', then computes a new value `V = S-O+366-(F'>>3)` modulo 2^32.
- Otherwise let R=S-O and K=366-(F>>3). If R<=K unsigned, it preserves Y and takes V=R.
- If R>K unsigned, the code increments Y under an overflow check, loads its new table byte F', and takes V=R-K.

The increment and decrement operate on signed low32 EDI and have explicit JO edges. The post-adjustment table byte is used in subsequent packing. These facts describe integer paths, not a proved calendar conversion, date constructor type, timezone or public API. `arithmetic.json` retains every raw F, L, O and K table row; it does not simulate this function's instruction stream.

## Final bounds, packing and returns

The next wrapped comparisons locally admit the adjusted coordinate Y only in **[-262143,262142]** and V only in **[1,366]**. Otherwise the initialized zero result is returned. The admitted path computes, in u32 arithmetic:

```text
P = (Y << 13) | (V << 4) | zero_extend(F)
return P if (P & 0x1ff8) < 0x16e1 unsigned; otherwise return 0
```

The final mask is separately observed; it is not dropped simply because V passed the earlier range. EAX-writing instructions zero-extend the full ordinary-return RAX. The entry `push rax` / final `pop rcx` restores the incoming RAX bits into RCX on these ordinary returns; no broader scratch-register ABI is claimed.

On decrement overflow, control reaches `0x1628f36` and calls through `0x64df848`; if that call returns, the next block also calls through `0x64df520`. Increment overflow enters that second block directly at `0x1628f43`. The second call ends this FDE. No ordinary epilogue from these helper paths is established inside the range, and no panic/nonreturning type is invented.

## Controls and remaining gaps

Observed verification covers 384 bytes, 103 instruction rows, eight conditional/short branch records, both indirect calls, their RIP operands, actual FDE/CIE and the entire table. Eight downstream mutations reject: five exact body-range locks, then independent table-byte, FDE-extent and relocation checks. The first five are **hash admission controls**, not semantic execution proofs. A separate real reciprocal-immediate counterfactual (`C xor 1`) disagrees with independent truncation division at witness 400; this is a scalar equation check, not patched-target execution.

No Rust implementation/build, byte identity comparison, hosted CI or container result is claimed. The required full suite remains unrun and the PR remains draft. Source types, valid caller domain, error helpers, caller provenance and whole-node behavior are unresolved. All reconstruction gates remain false.

Next question: establish one real #115 caller and its admitted raw domain before assigning source-level calendar meaning or implementing the constructor in Rust.
