# RE-008: request-throttle state transition, node94

This pre-code packet proves a bounded request-throttle operation under explicit
memory, tree and external-call premises. It connects general row/reason insertion
to retained timestamps, every binary64 delay class, canonical-calendar addition
and the one-shot result. It contains no Rust implementation or captured execution.

Start with [CONTRACT.md](CONTRACT.md), then [PROOF.md](PROOF.md) and the explicit
[external call frame](CALL-FRAMES.md). The proposed safe
API and input-only qualification route are in [SOURCE-PLAN.md](SOURCE-PLAN.md)
and [PROTOCOL.md](PROTOCOL.md). The proof separately labels newly specified
InvalidTime/DeadlineRange refusals; finite fixture agreement cannot establish
universal native correspondence.

Merged [PR951](https://github.com/lalalune/hyperliquid-source/pull/951), by
dbstkddl8-create, already recovered the commit caller's default one-second
one-shot outline. It explicitly left row creation and Chrono/year rollover
stubbed and supplied no Rust. This packet credits that work and closes those
value/state helper boundaries. Open
[PR1473](https://github.com/lalalune/hyperliquid-source/pull/1473) owns the exact
packed-date-add helper and standalone source; it is credited mathematical/native
context, with no copied source or unmerged dependency. Request pruning, sent-flag
reset elsewhere, logs/locks/allocator internals, outbox readers and networking
remain outside this operation.

The target is node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
There are 9 core/helper FDEs (10,639 bytes / 2,306 grouped rows) and 3 full caller
contexts (17,366 bytes / 3,289 rows). Both native decoders agree on all 28,005
bytes / 5,595 rows. All 2,362 instruction obligations, 10 data spans, 62 selected
relocation slots and the full 80,300-entry relocation census are checked. Counts describe this
bounded evidence; they do not advance a repository completion gate.

The independent corpus has 949 histories / 3,776 calls, including 15 histories
that exercise the new safe refusals. Mathematical certificates cover 66 nonfull
tree gaps, 12 full-node split/edge identities, every entry in the 146,097-day
calendar cycle, 524,286 canonical year boundaries and full-range reciprocal
inequalities. The 13,216 host float examples challenge the binary64 derivation;
they are not an exhaustive 2^64 test or target execution.

Reproduce from the repository root, with Python3 and GNU/LLVM native disassemblers:

```
python3 -B research/work-items/RE-008-request-throttle-94/verify.py --out /tmp/throttle-a
python3 -B -O research/work-items/RE-008-request-throttle-94/verify.py --out /tmp/throttle-b
```

`--binary`, `--gnu` and `--llvm` permit explicit providers. Defaults are the
recorded macOS host paths. Raw native text is version-sensitive; the exact
recorded provider identities are in tools.json. Only the private snapshot filename
is normalized to hl-node in retained native stdout. Every target is admitted by
the full SHA/size before native parsing. Providers never execute the captured
program. Below-identity byte controls are explicitly test-only mutated data
decoded afresh in full FDEs; they do not bypass admission for a real target.

PRE-RUST-FREEZE.json binds the final pre-code inputs and author validation
receipts; no source/client/build files exist. The parent/peer gate decides whether
source authoring may begin. Research and live-PR sources have one project/target
lineage; multiple decoders/reviewers are not independent captured executions.
Actual author commands and limits are recorded in [VALIDATION.md](VALIDATION.md).
