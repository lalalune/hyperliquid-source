# RE-006: correct the book-ring first-word attribution

The retained book-ring producer and records incorrectly identified element0
as the cached level+0x28 qword. Both actual node115 twins reload R15 from a
different saved word before storing element0. A reconstruction following the
old record would therefore copy the wrong value when those words differ.

Target Linux x86-64 node115,105896032 bytes, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base05bc2de303c05525b71e7e257426e741bc66a390; unrebased ELF VAs.
RE-006/orderbook, under approvedScope. This corrects an actual interpretation
defect in merged #2416. Related #2427/#2441/#2447 describe shared returns,
caller forwarding and forward callees; they do not repair this attribution.
Live all-state address, ring/cached, book/field and ring/source searches found
no competing correction within indexing/unpublished-work limits.

## Original counterexample and corrected flow

The same original-instruction reproducer failed against the unchanged record
before correction: saved order word17, cached level word900, actual field0=17
in BOTH twins, while the old declaration predicts900. The first exploratory
failure is retained; the explicit prediction-comparison run failed in4.903s.
Original producer/records/README were preserved externally and in the base Git
revision. Captures and retained native exports are preserved.

The actual caller-local flow is pinned in each twin:

| Step | Twin A | Twin B |
| --- | --- | --- |
| Bind order RSI to R12 |0x59118a7|0x5911b47|
| Load order+0xf0 into RBX |0x59118d1|0x5911b71|
| Save RBX at stack+0x30 |0x5911980|0x5911c20|
| Reload R15 from stack+0x30 |0x5911a53|0x5911cf3|
| Store R15 into element0 |0x5911ac2|0x5911d62|

On the derivation-zero arm, the cached level+0x28 value is supplied to the
shared insert routine. On the nonzero arm, the body reads through RDX after
the derivation call; its pointee identity remains unclosed. This branch
distinction is retained instead of assuming both paths use level+0x28. The later reload overwrites that carrier before the ring
store. No equality between cached and saved words is inferred. This static
def/use binding assumes ordinary callee-saved-register and caller-stack
behavior; it does not implement or prove arbitrary opaque helper effects.
The producer now checks the five real sites and records the origin explicitly,
including actual VAs for each twin, rather than emitting an unsupported label.

## Qualified original tail replay

native.py independently seeds the post-callback tail at each owner+0x1f0.
R14 is the level pointer, R15 the fresh saved-word input, RBP the fresh dword,
RBX the retained return word, and stack+0x68 the fresh16-byte copy. Valid
disjoint ring objects, head/length/capacity invariants and a valid existing
frame are premises. Other registers/flags start unknown; frame bytes and
buffers are explicitly synthetic canaries. This is NOT a supplied callback,
proof of callback return or composed whole-insert trace.

Ordinary paths execute actual RET and check returned RAX and restored RSP.
Observe the complete level/buffer snapshots. Only28 of each32-byte element
are written (8+4+16); bytes28..31 remain their caller-provided values. Full
capacity stops BEFORE the actual grow call, with memory unchanged; growth,
lookup, allocation, other helpers, unwind and caller reachability remain open.
No raw diagnostic/grow frontier is renamed into a native error or result.

Broader regression fixtures are collected after the metadata correction and
are not described as a pre-implementation oracle freeze. The initial two
counterexamples predate the correction. Expected snapshot streams come only
from the authenticated original instructions, not an invented append model.
The unchanged MIT project instruction CPU and ELF View from
RE-014-price-core-115 are credited reuse; no unlicensed inferred source copied.

## Reproduce

From repository root after source ../hl-env.sh:

    python3 tools/book_ring_append_static.py
    python3 research/work-items/RE-006-book-ring-source-fix-115/native.py
    python3 research/work-items/RE-006-book-ring-source-fix-115/proof.py --output <new-directory>
    python3 -m unittest discover -s tests -p test_book_ring_source115.py -v
    python3 -m unittest discover -s tests -p test_book_ring_append_static.py -v

Python3.12.14, Capstone5.0.6, GNUobjdump/readelf2.47.20260726, macOSarm64.
Serial0.10 active-wall duty limits local work; this is not a strict aggregate
CPU guarantee. A first full producer run hit its external240-second resource
bound; its failure and subsequent bounded diagnostic logs are preserved, not
reported as passes. Completed checks and any supporting blocker remediation
are recorded only after observed results.

No Rust reconstruction, captured executable/Unicorn, service, chain, signing,
wallet, original ABI, byte-equivalence or full-orderbook claim. All92 gates
remain false. New analysis/fix uses MIT. Next: close the actual grow and lookup
effects before composing a complete native insert path.

## Observed correction and corpus

The unchanged reproducer failed before correction in4.903s (actual17 versus
reported-source prediction900 in both twins), and passed after correction in
2.864s (both actual and declared prediction17). The complete producer passed
in270.019s with a larger external resource budget; no repository assertion,
input range or test was relaxed. Diagnostic samples identified full readelf
text filtering as the slow stage; no unrelated performance rewrite was added.
The original240-second incomplete run and45-second diagnostic run remain
recorded as incomplete, not passes. All native exports and frame text remain
byte-identical to base; only corrected semantic metadata changes there.

The target-backed corpus passes:1446 distinct fixtures,1224 actual ordinary
RET snapshots and222 grow-call frontiers, with12 actual byte-COW controls.
The two selected tails total182 bytes/56 instructions and all56 starts are
visited. The complete two663-byte owners remain static context. Proof collection
15.246s PASS; proof.json retains exact input/output hashes, source bindings and
the old-declaration counterexample. This is finite point-state evidence, not
full insert-path equivalence or source implementation coverage.

The first existing-file regression attempt was intentionally interrupted when
this related shared-argument qualification was found. It is not counted as a
pass. Its raw partial log is retained; complete regression is rerun after the
related metadata correction. Both corrections concern the same carrier flow
and remain one contribution.

Final focused regression passes: all7 new target/source regressions in17.442s,
then all5 unchanged existing book-ring tests in945.103s, complete run962.848s
under0.10 duty. The existing tests freshly regenerate and byte-compare every
retained export, frame record and corrected JSON with the final producer.
No existing test/negative control was removed or weakened. Both source-word
corrections are included in that completed run. Exact commands/results are in
focused-checks.json. The earlier interrupted run is not substituted for this pass.

## Scoped repository verification

Twelve packet-integrity tests, doctor, artifact/import/packet verification,
catalogue generation/check and actual inventory reproduction pass. Completed
scoped run391.852s; repository-checks.json retains exact commands and timings.
Only catalogue steps temporarily use the already-submitted #2655 immutable-
snapshot helper for its measured39.47GB repeated-read blocker. Both helper
hashes/scope are in validation-overlay.json; the baseline helper is restored
before reproduce/commit and is not part of this diff. These two steps are not
unmodified-head catalogue runs. The earlier six own upstream full passes belong
to separate PRs; this correction's own full CI is pending. No local full-suite
or hosted-CI pass for this head is substituted.
