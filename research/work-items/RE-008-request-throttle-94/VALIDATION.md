# Author pre-code validation

Both actual author commands completed with exit 0 before PRE-RUST-FREEZE.json
was created. Their complete validation receipts are byte-identical:
[normal.json](validation/normal.json) and [optimized.json](validation/optimized.json).
The command output directories were fresh private temporary directories; the
commands below preserve their actual options using logical output names.

```
python3 -B research/work-items/RE-008-request-throttle-94/verify.py --pre-freeze-check --out <fresh-normal-output>
python3 -B -O research/work-items/RE-008-request-throttle-94/verify.py --pre-freeze-check --out <fresh-optimized-output>
```

Each run admitted the complete target identity, regenerated two deterministic
native/corpus/certificate trees, matched all retained exports, and rejected
91 negative controls. It checked 12 full FDEs / 28,005 bytes / 5,595 grouped rows,
2,362 instruction pins, 10 data spans and 949 histories / 3,776 steps. The
9 operation/helper bodies account for 10,639 bytes / 2,306 rows; the remaining
3 full bodies supply caller context, not complete caller semantic theorems.
The corpus marks 15 histories containing new InvalidTime/DeadlineRange policies
separately from the conditional ordinary-return native relation.

The receipts enumerate every mutation and its actual rejection. Most byte
controls challenge exact binding below target/body identity after fresh full-FDE
decoding. Four controls separately challenge CFG ordering without instruction
pins, including a prefixed-branch bypass. These are static checker controls,
not executed target mutants or future Rust behavioral tests. The mathematical
certificates check finite cycle/sequence identities and reciprocal inequalities;
the 13,216 host binary64 examples do not establish an exhaustive all-bit result.
The manual class/tree/calendar arguments remain necessary.

A draft replay preceded the vote caller's 0.15 literal/history addition. The
retained final receipts cover that addition. Documentation was completed after
these final runs; no parser, oracle, expected bytes or controls changed afterward.
The final contract makes the RN-even, gradual-underflow and masked-exception
floating-point premise explicit. No captured program, instruction emulator,
Rust source, input client or build harness was executed or authored. No broad
repository suite was run for this pre-code packet.

For reproduction after the freeze, omit --pre-freeze-check as shown in README.
That mode admits every frozen input first. Its receipt contains the actual
freeze SHA instead of null; this expected metadata difference does not alter
native/corpus regeneration or the negative controls. Native text depends on
the recorded GNU/LLVM versions and executable identities in tools.json.

This author result is ready for independent root/peer review. It is not a source
implementation, build authorization, public submission or unconditional native
memory/runtime proof. One captured target/project lineage underlies the evidence.
