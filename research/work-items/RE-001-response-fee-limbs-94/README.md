# RE-001 / EVM RPC: selected response-fee raw limb calculation

Question: which raw fee words, comparisons and carry branches feed the selected
transaction-response output? This maps a bounded question in the response builder,
not a completed RE-011 gate, financial recommendation or live transaction test.
Files: the offline verifier/interpreter, focused controls and this packet.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Unlicensed reference lead: can1357-hl
`999556f6e0a474b8312db96ec3149e1c44e97c23`,
`evm_rpc/reth_eth_tx_builder_copied.rs`, seed `0x1606580`. No code is copied.

## Observations

All coordinates are ELF virtual addresses, no masks. Complete owner
`0x1606580..0x1606c6d`: **1,773 bytes / 363 instructions**; raw FDE/CIE and
body digest in `records.json` and `owner.capstone.txt`. This denominator is the
complete export; the modeled arithmetic window is only `0x1606a58..0x1606adb`.
It is entered conditionally after the present-context branch and field selection.

Context presence tests bit 0 at context `+0`. The two accumulated words are
read at context `+0x10/+0x18`. Let B be their combined unsigned raw 128-bit value
and L its low 64 bits. Selected maximum pairs reside at stack `+0x1e0` for tag
0, `+0x1f0` for tags 1/2, `+0x210` for tags 3/4. The priority pair for tag 2
is stack `+0x200`, and for tags 3/4 `+0x220`. Valid original tag/type reachability
is not independently established here.

On the absent-context route the selected pair is copied directly into the two
accumulated words. In the modeled present-context arithmetic window, let M be
the selected maximum and P the selected priority:

1. `CMP RCX,R12; MOV RDX,RAX; SBB RDX,0; JB join` compares M against the
   **zero-extended low word L**, not an independently established full B type.
   M<L keeps the original B words.
2. Otherwise `SUB RCX,R12; SBB RAX,0` computes D=M-L. Tags 0/1 use D;
   tags 2/3/4 select min(D,P) by two-word unsigned subtraction and CMOVB.
3. `ADD R12,RCX; ADC RBP,RAX; JB overflow` adds that delta to B. Carry out
   of the second word takes `0x1606b78`, whose Location resolves to
   `evm_rpc/src/reth_eth_tx_builder_copied.rs:51:21`; helper slot `0x576e118`
   resolves to `0x157b480`.
4. The normal output arm writes fixed words 1 and 0, then these accumulated
   words at output `+0x10/+0x18`. Remaining response layout is not modeled.

Thus for this raw selected window, output is B if M<L, otherwise B+D (tags
0/1) or B+min(D,P) (tags 2/3/4), checked at 128 bits. If B's high word is
zero, this specializes to the familiar max/base/priority formula. The high-word
test cases document the instructions, **not valid typed input reachability**.

## Inferences and limits

Fee/maximum/priority and variant names follow the reference and field context;
original Rust types, enum layout, valid input constraints and full caller chain
remain unproved. In particular this does not identify a vulnerability, claim
that arbitrary high context words are reachable, or change transaction pricing.
Hash initialization, signature copying, allocation/copy helpers, response layout,
entry dispatch, ownership and unwinding remain unclosed. No Rust/native build,
source equivalence or component gate is claimed.

Before: a reference formula without a caller-bound raw-limb denominator. After:
the exact selected operands, field selection, carry route and conditional
arithmetic are digest-bound and independently checked. Next question: establish
the original context and fee types and their caller-populated value domain.

## Reproduction and controls

Python 3.12.14; stdlib static ELF readers; optional Capstone 5.0.6, x86-64 Intel.
No captured instruction executes natively. The tiny interpreter uses synthetic
registers/RAM, rejects unknown instructions/escaped paths and has a step bound.

```
python tools/response_fee_limbs.py --out research/work-items/RE-001-response-fee-limbs-94/records.json
python research/work-items/RE-001-response-fee-limbs-94/export_disassembly.py
python -m unittest tests.test_response_fee_limbs -v
```

Six focused methods pass in 0.831 seconds. All 3,645 combinations of five
declared tags and three nine-value raw-pair boundary dimensions agree between
the actual selected arithmetic interpreter and an independent big-integer formula.
The boundary classes include high context words without claiming native validity.
Changing the actual SBB immediate changes the interpreted output; bindings reject
it. Further controls mutate presence/field operands, selection/overflow branches,
priority comparison, output fields, source Location, FDE extent and target digest.
Make is unavailable; required Python commands were run directly. Full suite:
**363 tests in 107.118 seconds; 7 failures, 16 errors, 21 skips**. All six new
methods pass. Existing Windows newline/POSIX-path and native-tool limits remain
failures; this independent branch excludes unmerged #227. Doctor reports missing
prerequisites. Eight artifact sizes/digests pass before missing GPG prevents
signature verification. Imports reject the Windows reference checkout;
catalogue-check rejects backslash paths. Reproduce stops at artifact verification.
No full-suite, hosted-CI, signature or native-equivalence success is claimed.
