# RE-001: fee-history candidate percentile comparison loop

- Component: EVM RPC support. Question: which raw binary64 comparisons make the
  selected percentile loop reject or continue?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, consulted as a lead only.
- Status: observed loop/field/count context and conditional raw-bit model.
  Complete RPC admission, legal inputs and FP exception state are unresolved.

## Reproduce

Repository root, CPython 3.12.14 on Windows:

```sh
python tools/fee_percentiles_static.py --out work/fee-percentiles-94.json
python -m unittest discover -s tests -p test_fee_percentiles_static.py -v
python research/work-items/RE-001-fee-percentiles-94/export_disassembly.py
```

Verifier/model/tests use the standard library. Optional export uses Capstone
5.0.6, x86-64 Intel syntax, inspected wheel SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
No captured code, RPC request, database, chain or network action executes.

Selected exports retain **134 bytes / 30 instructions**: raw count context,
the percentile-object pointer, optional/count/comparison loop and owner source
context. The full enclosing FDE `[0x27b6540,0x27b840b)` (**7,883 bytes / 1,506
instructions**) is decoded solely to validate instruction and branch-target
boundaries. Raw FDE/CIE and complete body hash are retained. No full fee-history
recovery is claimed. Addresses are ELF VAs; `.text` offsets are VA minus
`0x1000`. No masks.

## Captured loop facts

The optional word is addressed at future `+0xa8`. Raw INT64_MIN bypasses the
selected array loop. Other paths load its buffer at `+0xb0` and count at `+0xb8`.
For count below two, no percentile pair is compared. Otherwise each iteration:

1. Loads the previous element and UCOMISD-compares it with binary64 100.0 from
   `0x20a960`; **JA** selects the rejection join only for ordered greater-than.
2. UCOMISD-compares previous with next; **JBE** continues for less, equal **or
   unordered** results, assuming normal masked floating-point exceptions.
3. Advances eight bytes and decrements the remaining count.

The selected loop therefore rejects only `ordered(prev > 100.0)` or
`ordered(prev > next)`. It has no negative-value test, does not apply the 100.0
comparison to the final element, and performs no pair comparison for singleton
arrays. A raw pair [0,200] continues this loop; [101,NaN] rejects on its first
comparison. A raw [NaN,0] pair continues under the stated FP assumption.
Continuation is not overall request acceptance.

The nearby entry path branches to `0x27b66fa` for a zero raw count before these
comparisons and caps a larger nonzero count to five. Block-tag resolution,
provider requests, range arithmetic, output construction and later checks are
outside the model. No method-level behavior is inferred from the loop alone.

An owner-context Location binds to captured
`evm_rpc/src/reth_rpc_helpers_copied.rs:33:29` through `0x56c2ec0`; other
Locations in the owner include the copied reth fee-history source and evm_rpc.rs.
These support the candidate context, not a source line for every selected
instruction or a complete original function/type name.

## Reference comparison and declared population

The reference `validate_reward_percentiles` uses
`!(previous <= 100.0 && previous <= next)` for rejection. For unordered values
that form differs from the captured JA/JBE flag use. No implementation is copied
or reference input changed. The model computes relations with integer bit
classification/order keys, treating positive and negative zero as equal.

The declared population has 20 explicit bit patterns: signed zero/subnormals,
negative/positive finite values, values around 100.0, infinities and quiet/signaling
NaNs of both signs. All vectors of lengths 0..3 yield **8,421** model probes.
**2,920** differ from the reference's ordered-comparison form. This is an exact
count for that declared population, not all binary64 arrays or executed calls.
The model agrees with a separate Python comparison form for all probes.

**Assumption:** FP invalid exceptions are masked. UCOMISD signaling-NaN behavior
depends on MXCSR; that state and reachable NaN inputs are not recovered. No claim
that JSON permits these values, that a network request can reach these states,
or that this observation is a remotely reachable defect is made.

## Controls and required checks

Six focused methods pass. Actual-capture mutations cover UCOMISD operands,
unsigned conditions, upper-bound bits, count/optional/stride fields, raw cap,
source Location, FDE and identity. Make is absent; required Makefile Python commands were run directly. Full suite:
**363 tests in 107.474 seconds; 7 failures, 16 errors, 21 skips**. All six new
methods pass. This independent main-based branch excludes unmerged #227. Doctor
reports missing native prerequisites. Eight artifact size/digest checks pass
before missing GPG prevents signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs retained);
catalogue fails on native backslash paths. Reproduce stops at artifact
verification. Those failures are not marked passed.

No full RPC/parser/value codec, caller/provider closure, valid API population,
runtime FP state, native build/equivalence, imported change, hosted CI or progress
gate. Next question: close upstream number admission and exception-state setup
before assigning an externally observable API policy.
