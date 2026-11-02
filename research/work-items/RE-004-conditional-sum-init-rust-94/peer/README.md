# Independent initializer review

Reviewed by 신준 using OpenAI Codex; the exact model identifier was unavailable.
No blocking finding in the complete source, input-only driver, proof, oracle,
static verifier, native validator, or fresh complete 45-byte leaf disassembly.

Reviewed source SHA-256:
`56732429a79b8b85502003323700a6232f442feb1239fd78d5eb9adb15990386`.
Reviewed proof SHA-256:
`1ac70c24a253c49b0cea8116aaa8f1157273092ccc7ffa4b9752532b7f97a066`.
`result.json` binds the other source, proof, verifier and frozen-input hashes.

The independent arithmetic replay matched all 9,690 frozen cases: 8,709 admitted
and 981 refused. It compared every status byte, full RAX/RSI/RDX value and all
128 output-image bytes, totaling 1,550,400 bytes. It imports neither the author's
oracle nor any reconstruction. It fills four sign bytes from the input sign bit,
adds the eight byte pairs with a carried byte, and writes an input-image snapshot
in the original store order. This differs from the author's unbounded signed
subtraction, whole-integer sum and immutable address dictionary. The independently
produced stream has SHA-256
`fb3f3a711c48bea1d99602b1ac7c0eac0727083281ba110d2523d0d73bbd8236`,
identical to the frozen expected stream.

The universal proof checks are separate from those finite cases. MOVSXD observes
only low32 RDX; it leaves all64 RDX bits intact. When that low dword is zero,
the sign extension is zero, so the conditional choice leaves the same RSI value
as unconditional modular addition. MOV EAX,1 fixes full RAX to1. The four output
fields are disjoint and have no intervening reads, making the source's address
order stores valid for the claimed final-state relation. The checked image
preflight bounds every later slice and rejects before mutation. The documented
exclusions for original faults, control aliases, MMIO, concurrent observation,
wrapped layouts and native ABI are necessary and correctly stated.

The reviewer manually parses ELF64 headers, program/section tables and all
121,299 actual FDE records, binding the three complete CIE encodings. It checks
the exact 45-byte leaf, separate three-byte padding, both unique complete caller
FDEs (4,389 and 4,113 bytes), their GNU/LLVM/Capstone partitions and the two actual
call boundaries. The three windows total8,547 bytes and1,718 instructions. A
fresh whole-.text E8/E9 scan finds exactly the two entry calls and no direct
candidate into another byte of the leaf or padding. All80,300 RELA records are
checked: none names any byte in that interval or writes into it. This does not
establish complete indirect reachability or caller behavior.

The author's static verifier was also run with `python3 -O -B`: all18 corruption
controls passed. `static-replay.log`, `fresh-gnu.txt`, and `commands.json` retain
the results and commands. The independent reviewer and static replay both exited
successfully on their first execution; no review failure was discarded.

Portable arithmetic/static review from the repository root:

```sh
python3 -O -B research/work-items/RE-004-conditional-sum-init-rust-94/peer/verify_independent.py
python3 -O -B research/work-items/RE-004-conditional-sum-init-rust-94/verify_static.py
```

The reviewer writes only stdout. Python3 and Capstone5.0.7 are required. No native
Rust replay, captured code execution, instruction emulation, network operation,
full-suite run, or source/oracle/freeze change was performed for this review.
