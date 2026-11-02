# RE-004: three object-status gates with full register returns

Node94:91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base56c0ec672bd8fdcfaa80f2db700a61e6240b3663 and reference gitlink
999556f6e0a474b8312db96ec3149e1c44e97c23 are unchanged.
This contributes one closed family without advancing a component/progress gate.

The independent `no_std` Rust library closes three complete leaves:
0x5382c90 (three-valued flag/count gate),0x5382d30 (pointer-gated byte) and
0x5382d50 (ordered status/counter gate). Together they contain121 bytes and
34 instructions. All conditional reads, full RAX/RDX outputs, raw nonboolean
flags and arbitrary read-role aliases are preserved. The last function's SETB
writes only AL: on its comparison path, RAX retains bits8..31 of the first
loaded dword. Returning only a bool would silently change the observation.

PROOF.md derives every branch, read width and full register. The immutable-image
API accepts only reached fields, including missing suppressed fields on early
returns, and supports modulo64 field addresses within a nonwrapping image.
None is a new safe admission refusal. The original ABI, flags, faults, MMIO,
races and control-stack aliases are outside the bounded value projection.

## Reproducible evidence

All three full FDEs/CIE, exact121 bytes and34 instruction boundaries, and
separate1/1/5-byte INT3 pads are authenticated with GNU, Apple LLVM and Capstone.
There are no captured helper calls or static-data dependencies. Full .text
E8/E9 scans find no direct candidates; this is not an indirect reachability
claim. Five symbol-zero RELATIVE slots name the entries: three in.data.rel.ro
and two in.got. Exact raw bytes, section/PT_LOAD mappings, addends and unique
writers are verified against all80,300 RELAs. All56 static corruptions fail.

The first static attempt incorrectly assumed all naming slots used.data.rel.ro.
It refused the actual.got mappings. The complete original verifier and diagnostic
are retained in initial-static-slot-section-failure.json.gz. The correction
binds each exact mapped section and leaves all writer/type/addend constraints
intact; it preceded the oracle freeze and any Rust source.

The pre-Rust immutable-address-map oracle freezes21,550 cases, with19,538
admitted observations and2,012 refusals. It uses ordered alternatives and
lexicographic byte comparison, independently of Rust's typed unsigned compare
and bit mask.4,055 admitted cases retain upper return bits, and5,942 return
nonboolean flag bytes. The native client receives only input descriptors/data,
never expectations. The immutable slice and forbid(unsafe_code) establish that
library calls cannot mutate images; native comparisons check status and both
full output registers without masks.

Compiler: rustc1.94.1, commit e408947bfd200af42db322daf0fadfe7e26d3bd1,
binary SHA-256 b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6.
Builds bind aarch64-apple-darwin, edition2024, denied warnings, overflow checks,
one codegen unit and the actual system linker. Static tools: GNU2.47.20260726,
Apple LLVM17, Capstone5.0.7. Only newly authored native Rust executes; no captured
binary, instruction emulator or original compiled-byte equality is claimed.

```sh
python3 -O -B research/work-items/RE-004-object-status-gates-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-object-status-gates-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/object-status-gates-replay
```

Use a new output directory. The compiler location may differ; identity stays
checked. Source/tool identities, exact commands, failures and native outputs
are retained. Frozen expectations are never regenerated from Rust outputs.

## Shared baseline limits

The separate baseline attempted971 files/15,462 tests/69 skips. Original exit2
was solely three disk-full errors; all20 affected tests passed isolated retries.
shared-baseline-result.json preserves this outcome and log hashes. No successful
full-sweep repeat, per-head full suite, skipped Linux run or hosted-CI success is
claimed. Imported evidence, pins, catalogue and generated gates are unchanged.

## Final qualification

All86,200 observations match four opt0/opt3 builds and repeats. Same-option library/client/output hashes match exactly. All33 compiled controls are effective:22 alter successful values;11 alter only safe admission in this finite corpus. No target-fault equivalence is inferred from those11. Three unit tests per optimization, malformed-input checks and both comparator controls passed. The lossless972,979-byte archive retains244 stdout/stderr streams from122 commands; verify_recorded.py independently checks every payload/command digest, source identity, full native result and mutant mismatch count. All33 mutant sources passed metadata compilation before execution. No native qualification failure occurred.

Doctor, verify, catalogue-check, reproduce, 28 focused predecessor/FDE/GNU tests and rustfmt passed; repository-checks.json.gz retains exact commands and outputs.

## Independent review

A separate reviewer read the full library, driver and proof, freshly decoded all121 bytes, and independently reproduced all21,550 expected records using contiguous scalar reads, unbounded subtraction and quotient/remainder reconstruction of the partial-AL result. Manual ELF64 section/PT_LOAD/FDE/RELA parsing confirmed all three bodies and five uniquely written naming slots. The supplied static verifier passed all56 controls. The parent reproduced the exact independent report. Source/proof/oracle stayed unchanged; no review failure, independent native replay or exhaustive image claim is implied.
