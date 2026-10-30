# RE-001: finite signed nanoseconds and normalized helper arguments

- Component: foundation. Bounded question: how does the prefix of `0x1459ca0`
  lower a scaled binary64 value to the integer arguments of `0x15206e0`?
- Target node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  reference pin `999556f6e0a474b8312db96ec3149e1c44e97c23` is unchanged.
- Status: instruction/data observations and a conditional architectural model;
  no complete date implementation, Rust reconstruction or progress gate.

## Reproduce

Repository root, CPython 3.12.14 on Windows:

```sh
python tools/time_delta_lowering_static.py --out work/time-delta-lowering-94.json
python -m unittest discover -s tests -p test_time_delta_lowering_static.py -v
python research/work-items/RE-001-time-delta-lowering-94/export_disassembly.py
```

The verifier/model/tests use the standard library. The optional last command
pins Capstone 5.0.6, x86-64 Intel syntax. Inspected Windows wheel SHA-256:
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`
(`capstone-5.0.6-py3-none-win_amd64.whl`). No captured code is executed.

`records.json` retains constants, original slot bindings, source Location,
17 post-multiply bit-pattern probes and comparison metrics. The decoder export
retains raw FDE/CIE records and the complete `[0x1459ca0,0x1459df7)` window:
**343 bytes / 77 instructions** with contiguous full-byte consumption. Body SHA-256:
`3eda2460cfdfd813865399592cdad572779804d5d71ba10b4b127040f3466bd7`.
VAs are unrelocated ELF addresses; `.text` file offset is VA minus `0x1000`.
The modeled prefix ends before call `0x1459d70`: 208 bytes / 47 instructions.

## Observed lowering

| Site/data | Established fact |
| --- | --- |
| `0x1459cb6`, data `0x20a220` | MULSD by binary64 1,000,000,000. Input units are not recovered solely from this constant. |
| `0x1459cc3..0x1459ce3` | Clear the sign bit of the scaled representation and compare to maximum finite binary64. The nonfinite branch reaches the conversion with XMM1 already zeroed. |
| Data `0x20acb8` / `0x20a7f0` | Finite values are clamped between exact binary64 -2^63 and +2^63. |
| `0x1459d11..0x1459d2c` | Truncate toward zero to signed i64; values above the last binary64 below +2^63 select `i64::MAX`. The unordered guard can select zero. |
| `0x1459d2c..0x1459d54` | Signed high multiply by `0x112e0be826d694b3`, arithmetic shift 26 and sign adjustment compute a truncating quotient by 1e9 and signed remainder. |
| `0x1459d54..0x1459d66` | A negative remainder subtracts one from the quotient and adds 1e9 to the remainder. At the following call RDX/ECX therefore carry a floor quotient and a nonnegative subsecond part. |
| Slot `0x576e8a8` | The first following helper is bound to `0x15206e0`; its internal behavior is not reimplemented. |
| Slot `0x576efb8` | A loader binding names this helper's entry. This is not a complete caller census. |

For scaled -1.0, the modeled integer tuple is `(-1 second, 999999999 nanos)`,
not the truncating split `(0,-1)`. Scaled +2^63 maps to `i64::MAX`; scaled
-2^63 maps to `i64::MIN`. A *nonfinite scaled result* maps to zero, while a
finite result outside the i64 interval clamps. The model takes bits **after**
MULSD: it does not mistake a finite input whose multiplication overflowed for
a still-finite scaled value.

The later error path references the 38-byte `NaiveDateTime + TimeDelta`
overflow diagnostic and a relocated source Location for chrono 0.4.38
`naive/datetime/mod.rs:1631:38`. Slots to `0x151f870` and the panic helper are
retained, but complete calendar/date acceptance and return semantics remain
outside this prefix question.

## Model and controls

Assumptions: masked FP exceptions, ordinary binary64 comparisons, DAZ/FTZ off.
The 17 bit probes include both zeros, subnormals, fractional truncation, both
integer limits, finite extremes, infinities and NaN encodings. Probe patterns
are architectural inputs, not claims that every pattern is reachable after
MULSD or that signaling-NaN exceptions were observed on a running node.

The integer multiply-high/shift/correction model is independently compared
with Python's arbitrary-precision `divmod` on **16,417 distinct signed i64
samples**, including both extremes and negative remainders: **0 mismatches**.
This sample count is not exhaustive 2^64 coverage, executed target calls or
a whole-function equivalence denominator. The tests include explicit negative
counterexamples for omitting the remainder correction.

Six test methods pass. Actual-capture corruption controls change the multiplier,
clamp data, finite branch, division magic/shift, remainder correction, FDE size,
incoming/helper slot addends and input identity. Models are subordinate to the
original instruction/data locks; no unlicensed reference implementation is used.

## Required checks and limits

The Makefile Python equivalents were run because make is absent. Full suite:
**363 tests in 110.243 seconds; 7 failures, 16 errors, 21 skips**. All six new
tests pass. This independent main-based branch excludes the unmerged #227
output fixes; other limitations include missing binutils, Windows path assertions
and temporary-directory cleanup. Full-suite/hosted-CI success is not claimed.

Doctor reports missing native prerequisites. All eight artifact digest/size
checks pass, then GPG absence prevents signature verification. Imports fail
on the Windows reference checkout; reserved `node/aux.rs` and hydrated unstaged
LFS inputs are preserved. Catalogue fails on native backslash paths. Reproduce
is attempted and stops at artifact verification; no imported evidence is rewritten.

The selected native/reduced provider is not run. The input datetime layout,
calendar bounds, consumers of the result, runtime retry/deadline meaning,
full helper/caller closure and Rust build remain unresolved. No captured binary,
network or chain action runs. Next question: close the two following chrono
helper contracts before assigning a complete recovered time-add method.
