# RE-007: supplied flat margin-table range and predecessor

Component: `risk`. Target: Linux x86-64 node #115, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `05bc2de303c05525b71e7e257426e741bc66a390`. Coordinates are original
ELF virtual addresses, with file mappings retained in the native evidence.

This contribution implements the actual flat-table range selection needed
before a margin row can be consumed. Given physical 40-byte rows, a head,
live length and unsigned query, the independently authored Rust component
returns the two borrowed spans of live rows whose keys are at most the query,
plus the final included row's identity and fields. It accepts the table itself;
the caller does not supply a preselected row or lookup answer.

The range contains the complete logical prefix. Equal keys across the wrap
seam therefore select the last logical equal row. The final row supplies a
u64 field at byte 24 and a byte at 32, including zero. No margin arithmetic
or divisor validation is performed here.

## Gap, ownership and prior credit

The current main has no implementation registered for the risk component.
[PR #2223](https://github.com/lalalune/hyperliquid-source/pull/2223)
already established the margin formulas and caller evidence.
[PR #2252](https://github.com/lalalune/hyperliquid-source/pull/2252)
established related metadata-selection context. Those findings are credited;
these bytes were already included in earlier static censuses.

Current [PR #2834](https://github.com/lalalune/hyperliquid-source/pull/2834)
implements selected-row arithmetic while leaving `0x3cd80d0` as an opaque
lookup. This packet implements the supplied flat-table operation preceding
that arithmetic and does not copy or replace the arithmetic source.
[PR #2957](https://github.com/lalalune/hyperliquid-source/pull/2957) owns the
different metadata/exact-key selector, and
[PR #3053](https://github.com/lalalune/hyperliquid-source/pull/3053) owns other
32/56-byte exact-match searches. Their immediate seam-equality behavior must
not be substituted for the included-upper-bound operation here.

The initial live intake read all 596 open PR metadata records and inspected
the relevant source paths and discussions. Search results alone were not
treated as proof of absence. A new source path and evidence packet isolate
this contribution; no existing contributor's branch is modified.

## Native evidence and safe interface

The selected complete bodies are the 228-byte upper-bound helper
`0x4550ee0..0x4550fc4` and 450-byte range wrapper
`0x3cd80d0..0x3cd8292`: **678 bytes / 210 instruction rows**. The implementation
covers the wrapper's flat representation, unbounded lower bound and included
upper bound. Complete exports preserve the other branches without claiming
to implement them. The two margin leaves provide credited predecessor
context, not additional implementation coverage.

Read [the conditional proof](native/PROOF.md), the native bindings and
[the frozen host contract](reference/HOST-CONTRACT.json).
The correspondence assumes valid, stable, nonwrapping native storage,
nondecreasing live u64 keys, the selected bound tags, and separation of
mutable native output frames from the borrowed input. The tree sentinel,
other bound tags and generic failure paths are excluded. The selected valid
path calls the included-upper-bound helper and needs no opaque numerical or
overflow hook.

The safe Rust library borrows `[[u8; 40]]`, validates bounds before live-key
order, and performs a logical binary upper-bound search. A linear reference
uses a separately authored traversal and literal manual projections. Checking
order once costs O(live); each subsequent query costs O(log live). This safe
representation avoids native pointers, allocation and unsafe code in the
library. It is a chosen source API, not a recovered Rust layout or ABI.

When the prefix is empty, both returned spans are the backing slice at
`[0..0]`, matching the wrapper's canonical empty endpoints. The optional
predecessor is `None`. That host result does not claim the downstream margin
callers return normally on their diagnostic paths. Bounds/order refusals
and the driver protocol are also explicit host policies.

## Reproduction and validation

The source is [node115-margin-range](../../../src/node115-margin-range).
The packet retains a pre-source reference/corpus freeze, twelve literal
manual projections and slice lists, a deterministic generator, compressed
inputs/expectations, compiled mutation specifications and raw validation
streams. See [VALIDATION.md](VALIDATION.md) for actual commands, outcomes,
initial failures and limitations.

From the repository root, with Python 3 and an installed Rust toolchain:

```sh
python3 -I -B -S research/work-items/RE-007-node115-margin-range/native/verify_static.py \
  --target artifacts/node/115/hl-node --out /absolute/path/to/new-static-results
python3 research/work-items/RE-007-node115-margin-range/reproduce.py \
  --cargo /absolute/path/to/toolchain/bin/cargo \
  --out /absolute/path/to/new-outside-repository-directory
```

The reproducer checks source/corpus pins, builds isolated copies offline,
and gives the authored driver only input rows on stdin in an empty working
directory and environment. Expectations remain in the parent process.
This is input separation, not an operating-system sandbox. Only newly
authored host code is executed; the captured node is read as static data.

## Limits and next question

The result is conditional static correspondence and finite host validation,
not captured-runtime or whole-node equivalence. No source-built byte-window
comparison or first-byte discovery is claimed. Constructors, native table
reachability, tree representation, other range bounds, original error/unwind
effects, concurrency, financial units and full margin policy remain open.
The borrowed immutable API does not establish native ownership or lifetime
rules. All **92 component acceptance gates remain false**.

The next integration question is how authenticated constructor state supplies
this flat view and how its selected row composes with the separately owned
arithmetic implementation. No integrated margin or node claim is made here.
