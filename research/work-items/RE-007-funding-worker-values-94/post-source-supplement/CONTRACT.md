# Post-source guard-order supplement

This supplement was proposed and approved after the first actual compiled
qualification. It is not part of the historical pre-source corpus. The original
10,945 cases, all original expectations, source, driver, harness and chronological
freezes remain unchanged. `FIRST-RUN.json` and `rust-validation/first-run/` retain
the actual first-run failure: 14 of 15 executed mutants differed; the fifteenth,
`size-before-index`, survived those cases. The sixteenth had not run. Both
production profiles and clean rebuilds matched all original cases.

The missing boundary is independently established by `PROOF.md`'s metadata
bounds check before the zero-size skip, and by the source-frozen integration
test `guard_order_precedes_size_and_raw_time`. The original corpus did not
include that combination. This supplement fixes the qualification gap, not a
production value mismatch. It does not retroactively give the first run a pass.

Exactly two cases use new opaque IDs `0x8000000000000000` and
`0x8000000000000001`. Both have address and raw time all zero, bypass byte one,
empty membership, shared balance zero, the single rate `(asset=0, raw=+1.0)`
and the single position `(asset=0, tag=0, local_balance=7, size=0,
accumulators=[0,0,0])`. The cases differ only in metadata:

| Case | Metadata | Independently required result |
| --- | --- | --- |
| A | empty | Refusal, asset zero, `MetadataIndex` (raw reason zero) |
| B | `[0]` | Accepted unchanged state, no rows or requests, sum zero and no maximum |

For A, bypass admits the worker and the present nonzero rate reaches index zero.
The empty metadata rejects that index before either size zero or raw time zero
can skip it. For B, the index is in bounds and size zero skips subsequent work;
the one position and shared balance remain unchanged, with an empty result
stream and its empty summary. No floating arithmetic, saturation or hidden
native failure state is needed to derive either expectation.

`oracle.py` writes these two input frames and directly specified result frames
using only the already frozen binary protocol. It imports no production source,
driver, original oracle or expected corpus and performs no target execution.
The result layout is independently enumerated; no fold or source result is used
to infer the expected values. A separate supplement freeze must precede rerun.

`build-supplement.py` admits both the original source freeze and the supplement
freeze. It compares original and supplemental output partitions separately and
also compares their complete combined stream. All 16 original mutations run
again against the combined 10,947 cases. A mutant counts only when it compiles,
exits successfully, emits all frames and differs in actual value output. The
new cases and the passed continuation are always labeled post-source; native
conditional scope, allocation/refusal limits and build reproducibility limits
are unchanged.
