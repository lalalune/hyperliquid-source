# RE-001: packed u32 fields to character-like callback arguments

- Component: `foundation`; one independent bounded formatting/layout question, unrelated to the TLS, gossip and storage packets.
- Target: node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Included: complete `[0x151f240,0x151f44f)` FDE, **527 bytes / 158 instruction rows**, its 733 accessed table bytes, raw field arithmetic, selected helper-slot identities and all visible callback/return paths.
- Excluded: indirect callback/helper bodies, source-level input type, formatting traits, calendar validity, runtime callers, arbitrary alias effects, Rust reconstruction and target execution. No progress gate requested or changed.
- “Formatting”, “character-like”, “context” and “group” are descriptive inferences from the requested integer bytes and separators, not recovered source declarations. No inferred reference code, types, labels or tests were consulted or copied. New work is independently authored; captured bytes retain upstream rights.

## Gap, selection and independence

The complete 598-open-PR inventory in `work/fourth-prs.json` had no body/scope match for `151f240`, `151f43a`, `250675` or the packed-word/date-formatting question. The existing `foundation-twin-widen-94` packet covers neighboring `0x151f0a0`, `0x151f100` and a boundary at `0x151f160`, not this FDE. The existing millis/calendar conversion lead is at `0x151f6f0..0x151f86a`, also disjoint. Current repository packet/source searches found no prior interpretation of this FDE or its table. Recheck live work before submission; this screening creates no ownership claim.

Before: this function's packed input, table, callback arguments and return handling were not grounded by a packet. After: one complete static range maps the raw fields and accesses, finite four-digit arithmetic, table-dependent remaining groups, short-circuit paths and final EAX transfer. This is an ordinary independent formatting/layout contribution, not a split of another contribution or a continuation of the separately excluded storage work.

## Reproduce

Observed environment: macOS 26.4.1 (25E253), CPython 3.11.15, Apple LLVM objdump 21.0.0, optimized build. Work from repository root with the authenticated LFS artifact materialized:

```sh
python3.11 -B research/work-items/RE-001-packed-word-format-94/verify.py --negative-controls
python3.11 -B research/work-items/RE-001-packed-word-format-94/arithmetic-check.py
python3.11 -B research/work-items/RE-001-packed-word-format-94/capture.py --objdump /Library/Developer/CommandLineTools/usr/bin/llvm-objdump --output work/packed-format-recapture
```

The output directory must be new; another host may supply its installed LLVM objdump. These scripts read the authentic ELF and invoke only the local static disassembler. No captured executable, instruction evaluator, callback, compiler, network, chain action or model call runs.

`capture.py` is the exact command recipe: one LLVM `-d --start-address=0x151f240 --stop-address=0x151f44f` export and `--dwarf=frames` selection. It creates `formatter.objdump.txt`, `frames.txt` and `evidence.json`. A second new capture reproduced all three outputs exactly. The input path label is normalized to the repository-relative artifact name; no instruction/operand/data normalization occurs.

`verify.py` independently checks the complete artifact hash, section-resolved mappings, exact supported CIE/FDE, complete nonduplicated instruction-byte coverage, branch displacements, selected RIP references, all twelve indirect-call encodings, three unique relocations and the 733-byte table. The parser/checker adapts independently authored earlier static evidence scripts. `verification.json` records eleven rejected corruptions below the outer digest gate. `arithmetic.json` retains the separately described mathematical checks; they do not evaluate captured instructions or execute callbacks.

## Actual range, data and boundaries

All coordinates are **ELF virtual addresses** without a guessed runtime/Ghidra rebase. The function maps to file offset `0x151e240`. FDE `.eh_frame+0x14fec` has actual PC/range `[0x151f240,0x151f44f)` under the observed `zR` pcrel signed-32-bit CIE. The raw record and independently produced LLVM frame output agree. Padding after the exclusive endpoint is not part of the 527-byte body. Nearest-symbol annotations do not identify this function.

The 733 bytes at `0x250675` have SHA-256 `a68431dafc3ea79ecc7641b371fdef73cca6769fbe20a95d9d15f1cca9c980a2`. They are retained in full in `evidence.json`, without assuming that this is the entire source object's extent. The bound is grounded by the actual unsigned comparison before the byte load.

Three unique `R_X86_64_RELATIVE` records provide these link-time addresses:

| Slot | Link-time target | Visible use |
| --- | --- | --- |
| `0x576eb58` | `0x15706d0` | Pointer placed in a stack descriptor for the large/signed branch |
| `0x576e008` | `0x1571d90` | Indirect descriptor/helper call at `0x151f376` |
| `0x576dfc8` | `0x157b64f` | Indirect guarded-index failure call at `0x151f449` |

These are selected static bindings, not recovered source names, proof of runtime rebasing or complete helper closure. The context-loaded callback at offset `+0x20` remains runtime data, not one of those fixed bindings.

## Raw input fields and guarded table lookup

The function loads the first **u32** from the input pointer in RDI. It computes:

- `A32 = arithmetic_shift_right_i32(raw,13)`, retaining the resulting 32-bit pattern in R13D and on stack.
- `I = (raw >> 3) & 0x3ff`, using an unsigned shift/mask in EBX.

It compares I unsigned with `0x2dd` (733). For `I>=733`, control goes to `0x151f43a`, passes `rdi=I`, `esi=733`, `rdx=0x5672200` and calls through slot `0x576dfc8`. That call ends the selected FDE. No normal-return continuation inside this FDE, panic type, valid caller-input domain or source-level exception contract is established.

For `I<733`, a zero-extending byte load reads `T[I]` from `0x250675` and retains it for the later groups. The next branch compares **A32 unsigned** against 10,000. Consequently negative signed extraction results take the large/signed branch as well. Bits 0..2 do not participate in these extracted selectors; this is not a claim that arbitrary callback side effects cannot observe aliased input memory.

## Four-digit branch and opaque alternative

When unsigned A32 is below 10,000, write `A` for its value 0..9999. The target's arithmetic computes:

```text
H = (((A >> 2) * 0x147b) mod 2^32) >> 17
K = ((H * 0xcd) mod 2^16) >> 11
R = (A - 100*H) mod 2^32
Q = ((R * 0xcd) mod 2^16) >> 11
```

The four successive ESI requests are `0x30|K`, `0x30|low8(H-10*K)`, `0x30|Q`, and `0x30|low8(R-10*Q)`. `arithmetic-check.py` independently compares these derived expressions with Python's four-digit decimal representation for **all 10,000 values in this explicit branch domain**. They agree; the two independently computed output-stream hashes are retained. This establishes a finite arithmetic identity, not source year semantics or native output behavior.

This branch loads a context word from `[RSI]`, a second word from `[RSI+8]`, and a function pointer from that second word `+0x20`. It caches the pointer for successive calls, passing the context as RDI and each integer request as ESI. Ordinary ABI preservation of saved registers and normal callback returns are assumptions. Calling the second word a vtable and the function a character writer is an inference; callback identity, actual byte emission and side effects are not proven.

For unsigned A32 at least 10,000, the function instead places the address of its stored A32 pattern and the pointer from slot `0x576eb58` into a stack descriptor. It calls through `0x576e008`, passing the loaded context/second word, constant pointer `0x20ad18` and that descriptor. On a zero AL return it loads the current callback pointer from the saved second word `+0x20` and proceeds. The helper's formatting/sign/padding rules and aliases are unresolved. No complete text for negative or large values is invented.

## Remaining groups from the table

After the prefix branch returns normally with AL zero, the shared path first requests integer `0x2d` (`'-'`). It then adds the retained unsigned table byte to I in a 32-bit register: `B=I+T[I]` (mod 2^32). The observed guarded domain cannot overflow that addition because `I<=732` and `T[I]<=255`.

The next two requested bytes are:

```text
b0 = 0x30 + (B >= 640)
G = B >> 6
b1 = low8((G if B < 640 else G + 246) | 0x30)
```

Another `0x2d` request follows. The last pair uses `D=((B & 0xff)>>1)&31`, `Q=(26*D)>>8`, and requests `0x30|Q` then `0x30|low8(D-10*Q)`.

The independent arithmetic check retains **all 733 table-index rows**. For these actual bytes, the resulting high numeric group is 0..12 and the low group is 0..31; the requested suffix equals the zero-padded decimal text `G-D`. The `26*D` identity equals integer division by 10 for every D in 0..31. The literal raw case `I=0,T[0]=0` requests `00-00`. This is deliberately **not** interpreted as a valid calendar date, month/day type or reachable caller input. Table index duplicates and calendar-like output do not establish the missing source validity invariant.

## Callback short-circuit and full return facts

There are ten runtime callback call sites and two fixed-slot indirect helper calls in the complete FDE. On the small-prefix path with all earlier AL returns zero, the integer-request sequence has the four prefix requests, separator, two group requests, separator and two final requests. The alternative prefix delegates its own requests to the opaque helper rather than claiming four digits there.

The early runtime call sites are `0x151f2c8`, `0x151f2e9`, `0x151f317`, `0x151f336`, `0x151f38e`, `0x151f3aa`, `0x151f3ce`, `0x151f3dd` and `0x151f418`. Each has a subsequent AL test whose nonzero branch reaches the common epilogue with **CL=1**. The opaque-prefix helper at `0x151f376` has the same low-byte handling. These branches return **AL=1**, but do not necessarily define all of EAX to 1: writing CL preserves the other bits of ECX, which opaque callbacks may clobber. The epilogue copies ECX into EAX. No source bool ABI or high-bit invariant is invented.

The final callback at `0x151f433` is different: `mov ecx,eax` at `0x151f436` copies its complete returned EAX, and the epilogue copies that value back. There is no final AL normalization/test before return. Thus this final path forwards the callback's **entire EAX**, whereas earlier failures establish only low byte 1. All original instruction bytes and register/indirect call encodings are retained.

At the fourth prefix callback, `test al,al` at `0x151f339` supplies the later JE flags; the intervening CL assignment and EBP reload do not overwrite those flags. This corridor is not replaced with an assumption that every callback returns a normalized boolean. Actual emitted output, faults/unwinds, alias mutations and violations of the ordinary calling convention remain outside the claim.

## Verification, limits and next question

Whole-input identity, the complete FDE/CIE, 527 body bytes, 158 instruction rows, one near jump, 13 short/conditional branches, twelve indirect-call encodings, six selected RIP references, three relocations and the 733-byte table pass the packet verifier. A second new capture reproduces all three generated outputs exactly; mathematical output is separately retained.

Eleven negative controls reject the extraction shift, guarded bound, unsigned prefix branch, decimal multiplier, callback slot offset, early AL test, suffix threshold, final EAX-copy operand, table byte, FDE extent and indirect-helper relocation. They bypass only the outer image digest. **The first eight fail exact code-range byte hash locks**; table, FDE and relocation controls exercise independent structural checks. These are evidence-admission checks, not execution of mutated code, semantic mutation proofs or behavioral correspondence tests.

No Rust source/build, two-build result, source/binary identity, target execution, model-backed program, hosted CI or container result is claimed. Repository-wide checks are the integrating operator's separate results. All reconstruction gates remain false. Unknowns include concrete source fields, valid raw population, calendar semantics, callback identity, opaque helper effects, exceptional exits, callers and full formatting ABI.

Next question: establish the context/callback provenance and the opaque-prefix helper's actual descriptor contract, then connect valid packed inputs to source semantics before reconstructing a calendar-typed formatter.
