# RE-001 / consensus: history-result 20-byte membership

Question: what key width and search layout does the selected membership caller
use after a history lookup, and does its high-query diagnostic itself reject the
query? Scope: one caller, supplied synthetic tree model, controls and packet;
not complete stake/history/quorum semantics or a progress gate.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Unlicensed reference can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`,
`node/consensus/validator_set.rs`, supplies the seed/area as a lead only. The
reference's u32 ValidatorIndex abstraction is not assumed for this native search.
No implementation is copied.

## Observations

ELF virtual addresses, no masks. Actual FDE `0x44b3040..0x44b31fd`:
**445 bytes / 105 instructions**, full hash, raw FDE/CIE and complete contiguous
export. Only the selected caller/search protocol is modeled, not full history.

The query word in RSI is compared unsigned with state `+0x988`. A greater word
takes a diagnostic call through slot `0x576e978` to `0x143d010`, with Location
`node/src/consensus/validator_set.rs:78:13`. **If that diagnostic returns
normally**, both greater and <= paths continue to `0x42c9930` with state `+0x930`
and the query. Diagnostic policy, including possible nonreturn/panic, is unclosed;
this is not unconditional acceptance of future queries.

On a normal nonnull history-result route, the selected object provides root and
height words. The query key is copied from state `+0xaec` (16 bytes) and `+0xafc`
(4 bytes). Comparator slot `0x576e488` is independently resolved through its
actual GLOB_DAT relocation and dynamic symbol: **memcmp**, called with length
**20**. No four-byte/index comparison is inferred here.

The selected node search reads u16 key count at `+0x13e`, starts keys at `+0x60`,
advances 20 bytes, and normalizes memcmp's signed result. Query greater than key
continues scanning; equal returns AL=1. Lesser or exhausted keys choose the
corresponding child at `+0x140 + index*8`, decrementing height; absent/leaf-miss
paths return AL=0. The synthetic fixtures assume sorted, bounded node arrays,
mapped children and consistent heights. They are not claims about every valid
original Rust allocation or enum representation.

## Inferences and limits

Validator/history and address-like names follow the source context and width;
stake values, jailed-validator meaning, original key type and layout are not
assigned. History helper `0x42c9930` is opaque here; preliminary inspection shows
range/cache logic, so it is deliberately not replaced by a guessed floor lookup.
The selected model starts with a supplied resolved tree and tests membership;
no native history, validator state, memcmp call or captured executable runs.

Missing-history diagnostic effects, full caller domain, original tree ownership,
allocator invariants, helper selection/range behavior, concurrency, panic/unwind
and full boolean API semantics remain unclosed. Before: a source seed with broad
index/stake abstractions. After: real 20-byte comparator binding and selected
node search/return paths. Next question: close history-helper selection and
caller-populated key identity before assigning a typed validator-membership API.

## Reproduction and checks

Python 3.12.14, stdlib static ELF readers/synthetic byte RAM. Optional export:
Capstone 5.0.6 x86-64 Intel, no masks or native execution.

```
python tools/validator_history_member.py --out research/work-items/RE-001-validator-history-member-94/records.json
python research/work-items/RE-001-validator-history-member-94/export_disassembly.py
python -m unittest tests.test_validator_history_member -v
```

Six focused methods pass in 0.837 seconds. Synthetic null/empty/leaf/interior
trees through height 2 agree with an independent set membership oracle. All
5,120 single-byte changes of a 20-byte key verify full-byte identity. Changing
the actual comparator width to 19 creates a prefix match that the original
20-byte comparison rejects; binding checks reject that capture mutation. Other
controls cover diagnostics, lookup/comparator operands, keys/counts/children,
branches, source, synthetic RAM bounds, FDE and digest. These are partial
conditional checks, not native/stake/quorum equivalence. Make is unavailable;
required Python commands ran directly. Full suite: **363 tests in 163.396
seconds; 7 failures, 16 errors, 21 skips**. All six new methods pass. Existing
Windows newline/POSIX-path/native-tool constraints remain; this branch excludes
unmerged #227. Doctor reports missing prerequisites. Eight artifact sizes/digests
pass before missing GPG prevents signature verification. Imports reject the
Windows reference checkout; catalogue-check rejects backslash paths. Reproduce
stops at artifact verification. No full-suite/signature/hosted-CI or native
equivalence success is claimed.
