# RE-001 / node runtime: selected bootstrap inclusive window

Question: which raw current/target words produce an inclusive request interval,
and how do the 100-item limit and u64 boundary interact? Scope: selected arithmetic
tool, controls and packet. No complete bootstrap/network or progress-gate claim.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Unlicensed reference lead: can1357-hl
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `node/gossip_rpc_client.rs`,
seed `0x4389070`. Names are inferred leads; no implementation is copied.

## Observations

ELF virtual addresses, no masks. Actual FDE owner `0x4389070..0x438a38c`:
**4,892 bytes / 864 instructions**, with complete contiguous export, raw FDE/CIE
and body hash. Only `0x43892a6..0x43892f0` is interpreted. This is a bounded
selected arithmetic window, not semantic coverage of the complete async owner.

Before this region, a pointer is loaded from state `+0x88` and a word from its
`+0x108`. Call this C; call the target word already in RCX T. At `0x43892a6`,
unsigned C==T branches to `0x4389c32`, C>T to `0x4389e32`. Those are recorded
as equal/ahead branches; their full continuation/termination meaning is unclosed.
Only C<T enters the window-formation arm.

- `MOV RAX,RSI; INC RAX; CMOVE RAX,MAX` forms saturating C+1 and writes
  state `+0xa0`. Under C<T, C cannot itself be MAX, so the increment's overflow
  alternative is not reachable in this declared selected-path domain.
- `LEA RDX,[RAX+99]` gives the tentative inclusive end. The unsigned comparison
  against sign-extended `-99`, plus `ADD RSI,100; CMOVB RSI,MAX`, handles the
  near-MAX alternative. These instructions yield min(C+100,MAX).
- `CMP RCX,RDX; CMOVB RDX,RCX` caps that end at T; state `+0xa8` receives it.
- The same two registers are copied into future-state pairs `+0xd0/+0xd8` and
  `+0xe8/+0xf0` before the following helper work.

Thus conditional on reaching this compare with C<T, the stored interval is
**[C+1, min(T,C+100,MAX)]**, inclusive, with 1..100 elements. A request ending
at MAX is admitted by this arithmetic; equality does not make 101 elements.
The exact 17-byte LEA/overflow idiom has one match in `.text`, at `0x43892cd`.
This is only an exact-byte census, not proof that no differently compiled semantic
copy exists. The unsigned gates and stores are independently byte-bound.

## Inferences, overlap and unknowns

Current/target heights and bootstrap names follow the source lead and adjacent
logs; exact state types and caller ownership remain unresolved. PR #338 is an
inventory/call-edge census mentioning this owner; it does not establish this
arithmetic contract. PR #430's startup bootstrap owner `0x22b47c0` is separate.
This packet groups this window's equal/ahead/minimum/saturation and argument-copy
observations; it neither repeats #587's enum decoder mapping nor claims to run it.

An earlier lag/time gate can bypass the selected region and is out of scope.
Async entry/resumption, valid caller value domain, peer choice, request dispatch,
response verification, callbacks, state advancement and completion are unclosed.
No native/async thread, captured node, socket or peer is executed or contacted.
Before: a reference statement of at-most-100 windows. After: exact unsigned
arithmetic, inclusive endpoints and stored argument positions bound to the ELF.
Next question: close the response-driven state advance and resumption edges.

## Reproduction and controls

Python 3.12.14, stdlib static readers and a bounded selected-instruction
interpreter using synthetic registers/stores; unknown instructions/escaped paths
fail. Optional export: Capstone 5.0.6, x86-64 Intel.

```
python tools/bootstrap_window.py --out research/work-items/RE-001-bootstrap-window-94/records.json
python research/work-items/RE-001-bootstrap-window-94/export_disassembly.py
python -m unittest tests.test_bootstrap_window -v
```

Six focused methods pass in 1.885 seconds. A 325-by-325 raw current/target grid
checks 105,625 pairs (low words, near MAX and around bit 63), plus named inclusive
edges; all agree with an independent big-integer formula. These are conditional
raw states, not native caller reachability claims. Changing the actual LEA
immediate from 99 to 98 changes a derived interval from [1,100] to [1,99]; the
binding verifier rejects it. Other capture mutations cover gates, saturation,
minimum selection, state/future stores, FDE and identity. Make is unavailable, so
required Python commands were run directly. Full suite: **363 tests in 108.343
seconds; 7 failures, 16 errors, 21 skips**. All six new methods pass. Existing
Windows newline/POSIX-path/native-tool constraints remain failures; this branch
excludes unmerged #227. Doctor reports missing prerequisites. Eight artifact
sizes/digests pass before missing GPG prevents signature verification. Imports
reject the Windows reference checkout; catalogue-check rejects backslash paths.
Reproduce stops at artifact verification. No full-suite/signature/hosted-CI or
native-equivalence success is claimed.
