# RE-001/consensus: TC batch prefix guards and raw error stores

- Bounded question: what do the early helper-return, empty-batch and per-entry
  equality branches store before the later certificate checks?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; unchanged reference
  pin `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Status: static observations and a conditional prefix model. No recovered
  cryptographic verifier, complete Rust type or consensus completion gate.

The existing RE-008 wire packet identifies this candidate as `verify_tc` via
the direct call from `0x47b0439` and its edge to `verify_signed_timeout`.
It establishes wire/graph/quorum-compare evidence, not this prefix's register,
batch-layout and raw-error-store contract. Function/type names here remain
inferred; no reference implementation is copied.

## Reproduce

Repository root, CPython 3.12.14 on Windows:

```sh
python tools/tc_batch_guards_static.py --out work/tc-batch-guards-94.json
python -m unittest discover -s tests -p test_tc_batch_guards_static.py -v
python research/work-items/RE-001-tc-batch-guards-94/export_disassembly.py
```

Verifier/model/tests use the standard library. The optional export uses
Capstone 5.0.6, x86-64 Intel syntax. The inspected Windows wheel was
`capstone-5.0.6-py3-none-win_amd64.whl`, SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
Only Python/static decoding runs; no node, signature operation or network request.

`window.capstone.txt` retains the complete exact FDE interval
`[0x47594f0,0x4759963)`: **1,139 bytes / 244 instructions**, original FDE/CIE,
and contiguous full-byte consumption. Selected observations are checked to be
actual instruction starts. Body SHA-256:
`eb5f1f913174c49a88970690822c87031076f18c9966efe6356a5d145ea55696`.
Coordinates are ELF VAs; the `.text` file offset is VA minus `0x1000`.

## Original observations

| Site | Raw condition/data |
| --- | --- |
| `0x475950a` | Load input `[RSI+0x18]` into R14, then keep a stack copy. Calling it a round uses the existing TC interpretation. |
| `0x4759515..0x47595a4` | Compare against `[RDX+0x58]`; JBE skips diagnostic setup. The diagnostic arm's normal-returning path rejoins the same helper call `0x42c9930`. No new admission rule is inferred from this comparison. |
| `0x47595a9..0x47595b2` | Test helper-return RAX for zero. Zero branches to the raw tag/payload stores at `0x4759655`. The callee's full return type is unknown. |
| `0x47595e1..0x47595ee` | Load batch count from input `+0x10`; zero branches to `0x4759673`. Otherwise load entry buffer from input `+0x08`. |
| `0x47595f2..0x4759615` | Form `count*184`; iterate forward at 184-byte stride. Load each qword at entry `+0x50`, compare with the header word and stop on first mismatch. Valid backing memory/span is an assumption, not a recovered allocation contract. |

Error paths store these **internal raw bits**, not recovered wire discriminants:

| Branch | Output qword at +0 | Other observed output stores |
| --- | --- | --- |
| Helper return zero | `0x8000000000000028` | Header word at +8 |
| Nonzero helper result, empty batch | `0x800000000000000b` | No additional payload store claimed |
| First unequal entry word | `0x800000000000000f` | Unequal entry word at +8; header word at +16 |

These stores precede shared cleanup; arbitrary callee failure or nonreturn is
not modeled. Nonempty all-equal batches continue to later checks. That outcome
does **not** mean a certificate has a valid signature, adequate stake or quorum.
The remainder of the enclosing body is exported to establish boundaries, but
its full verification policy and helper closure are outside this question.

The diagnostic source Location at `0x5738668` is relocated to the
`node/src/consensus/validator_set.rs` path at `0x1f7ea2`, line 78, column 13.
This binds source context without treating the reference's pending quorum-seed
assignments as established function semantics.

## Models and controls

Nine recorded model probes exercise helper-zero precedence, empty/nonempty
batches, first mismatch, equal batches, zero and u64 limits. The helper flag
and entry words are abstract raw values; these probes do not prove all values
are reachable legal runtime states. The model assumes valid backing memory
and normally returning ABI-conforming callees, and stops at `later_checks`.

Six test methods pass. Actual-capture controls change the entry stride/field,
count/buffer offsets, equality/back-edge branches, tag base, empty adjustment,
mismatch payload displacement, source relocation, FDE length and input identity.
The model separately checks error precedence and preserving the first unequal
word. No new production verifier API or mocked signature service is introduced.

## Required checks and remaining gaps

Make is absent; the Makefile Python commands were run directly. Full suite:
**363 tests in 166.577 seconds; 7 failures, 16 errors, 21 skips**. All six new
tests pass. This independent main-based branch excludes unmerged #227's output
fixes; other problems include missing binutils, Windows path expectations and
temporary-directory cleanup. Full-suite/hosted-CI success is not claimed.

Doctor reports missing native prerequisites. Eight artifact size/digest checks
pass, then GPG absence prevents signature verification. Imports reject the
Windows reference checkout (reserved `node/aux.rs`, hydrated LFS files retained
unstaged). Catalogue fails on native backslash paths. Reproduce is attempted
and stops at artifact verification; original imports, pins and gates are unchanged.

No captured execution, signing, network/chain action, Rust build, full object or
wire-error layout, signature/quorum behavior, reachable-state proof or progress
gate is established. Next question: close the preceding helper return contract
and subsequent signed-timeout checks before constructing a complete TC verifier.
