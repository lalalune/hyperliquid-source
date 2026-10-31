# RE-001 / transport: LZ4 counter update and drain order

Question: which counters are updated/drained, and what is already changed when
a checked aggregate addition overflows or a bucket is skipped? Scope: selected
writer prefix and snapshot protocol, tools/controls/packet; no complete statistics
or concurrency reconstruction and no progress gate.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Unlicensed reference can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `net_utils/tcp/lz4_stats.rs`,
is a lead only; no implementation is copied.

## Observations

ELF virtual addresses, no masks. Full FDE exports: snapshot
`0x3d230c0..0x3d2328b` (459 bytes / 117 instructions), writer
`0x3d2a730..0x3d2abf0` (1,216 bytes / 261 instructions). Total **1,675 bytes /
378 instructions**, full hashes, raw FDE/CIE and selected boundaries. Only the
following protocol is modeled; whole-body export is not full semantic coverage.

Writer prefix `0x3d2a749..0x3d2a763` loads three pointers from handle `+0/+8/
+0x10`, then performs LOCK ADD at first pointer `+0x10` with RSI, LOCK ADD
at second `+0x10` with RDX and LOCK INC at third `+0x10`. These update before
the following trace-sampling gate. Machine additions wrap; this prefix has no
overflow branch. The reference's additional elapsed-time counter is not an
observed fourth update here; elapsed/tracing code beyond this prefix is unclosed.

Snapshot loads three counter pointers and executes separate XCHG-with-zero at
`0x3d23166`, `0x3d23173`, `0x3d23180`, yielding R14/R13/R15. **All three drains
precede the first aggregate-add check.** The three checked additions at
`0x3d23188/0x3d23197/0x3d231a6` write their aggregates one at a time after each
carry check. Overflow takes distinct captured Locations in
`net_utils/src/tcp/lz4_stats.rs:96:21`, `97:21`, `98:21`. Earlier aggregates
have already been written when a later addition overflows. No rollback appears
on these selected failure routes. This is not a transactional three-counter read.

After successful accumulation, input R14==0 or packed-key byte 48..55 equal
to 2 skips emitting that bucket. Drains and aggregate writes have already happened.
Otherwise two captured SIMD integer-to-double conversions and DIVSD compute
`double(output R13) / double(input R14)`. The normal 32-byte output stores key
pieces at +0/+4/+6/+7, input at +8, samples R15 at +0x10 and ratio at +0x18.
The original Rust enum/record type and the packed-key byte's meaning are unproved.

## Inferences and limitations

Input/output/sample names follow the writer operands, quotient and reference
context. The sequential model explicitly assumes distinct counter cells,
disjoint aggregate cells, no interleaving, normal helpers and ordinary nearest
floating rounding. Original pointer alias constraints, Rust atomic orderings,
concurrent snapshot coherence, Swiss-table traversal, trace logging, allocation,
panic/unwind effects and complete statistics layout remain unclosed. XCHG and
LOCK are observed machine operations, not proof of a particular Rust Ordering.
No live counters, native threads, captured binary or networking is used.

Before: reference narrative of snapshot draining including an extra elapsed
counter. After: three explicit updates/exchanges, ordered checked writes and
post-drain filtering are bound to actual bytes. Next question: establish pointer
ownership and producer/consumer interleavings before claiming a concurrent API.

## Reproduce and controls

Python 3.12.14, stdlib ELF readers; optional Capstone 5.0.6 x86-64 Intel.
No captured instructions execute natively.

```
python tools/lz4_counter_order.py --out research/work-items/RE-001-lz4-counter-order-94/records.json
python research/work-items/RE-001-lz4-counter-order-94/export_disassembly.py
python -m unittest tests.test_lz4_counter_order -v
```

Six focused methods pass in 0.821 seconds: all eight selected overflow-position
classes, all 256 packed flag classes with zero/nonzero/high input, wrapping
writer edges and captured conversion-magic bit comparisons around powers of two.
Changing a real accumulator ADD to SUB changes partial totals; changing the
filter immediate changes emission. Bindings reject both. Additional real-capture
controls cover updates, exchanges, overflow edges, source records, ratio/store
operands, conversion constants, FDEs and target identity. These are conditional
sequential checks, not a native or concurrent differential. Make is unavailable;
required Python commands were run directly. Full suite: **363 tests in 106.694
seconds; 7 failures, 16 errors, 21 skips**. All six new methods pass. Existing
Windows newline/POSIX-path/native-tool constraints remain failures; this branch
excludes unmerged #227. Doctor reports missing prerequisites. Eight artifact
sizes/digests pass before missing GPG prevents signature verification. Imports
reject the Windows reference checkout; catalogue-check rejects backslash paths.
Reproduce stops at artifact verification. No full-suite/signature/hosted-CI or
native-equivalence success is claimed.
