# RE-001 / transport: latency sampler's guards and normal-return update

Question: which guards select the two metric-update calls, how is the first
numeric value limited, and which state bytes are replaced before returning?
This is one source-linked static mapping question, not a recovered metrics API.

Input `artifacts/node/94/hl-node`,91774280bytes,SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Independent base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Exact FDE `0x3d22920..0x3d22a97`,375bytes,exclusive end. All addresses below
are original linked VAs; exported records include file offsets and range hash.
The denominator is these selected375bytes,not whole-node function coverage.

Actual source Location slots `0x57193b8` and `0x57193d0` both RELATIVE-bind to
`0x1f434f`, containing the embedded upstream path
`/home/ubuntu/hl/code_Mainnet/net_utils/src/abci_latency_sampler.rs`.
Pinned reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is preserved but
no inferred source implementation/comments are copied.

## Observations

1. The entry calls slot `0x576e8a0` (actual RELA addend `0x151cba0`) with a
   stack destination. Twelve bytes of that result are used later. A clock-like
   role is inferred from context; its complete clock/representation ABI is open.
2. Dword[input-object+0x7d0]==0 branches from `0x3d22945` to `0x3d229cd`,
   skipping the first measurement/update. Nonzero prepares previous-state and
   captured words for slot `0x576e8c0` (addend `0x1447130`).
3. The helper's XMM0 result is combined with binary64 literal60.0 at
   `0x20abf8` using `minsd %xmm0,%xmm1` at `0x3d229b0`. The destination
   started as60.0; for ordered finite values this is an upper cap, with no
   lower floor. The metric-like call at `0x3d229c7` uses slot `0x576efb0`,
   whose actual RELA addend is `0x14027b0`, with source Location `0x57193b8`.
4. Independently, BPL==0 branches from `0x3d229d7` to `0x3d22a4a`. A nonzero
   byte prepares another measurement and invokes the same metric-like slot at
   `0x3d22a44`, with destination object+0x260 and Location `0x57193d0`.
   This second route has no corresponding local60.0 MINSD cap in this body.
5. Both guard skips join the tail at `0x3d22a4a`. On every visible normal-return
   route, twelve bytes from the second incoming pointer and twelve captured
   bytes are stored into the24-byte region at object+0x7d0. Prior helper calls
   may have their own failure behavior; this does not prove they always return.

## Inferences and limits

The source and calls support a sampler/update interpretation. The dword guard
is not established as a complete initialization tag, nor BPL as an entire typed
enum. Units are not proven: literal60.0 is not automatically sixty seconds.
The raw MINSD instruction selects its source on an unordered comparison, so a
NaN source is propagated; this is not a finite-only clamp or complete validator.
Negative values also have no observed local floor. Caller reachability and
whether the helper can actually produce those values are not established.

Clock arithmetic, metrics accumulator behavior, initial object construction,
full type/layout/helper graph, concurrency and actual runtime behavior remain
unclosed. The helper0x14027b0 also appears in other mapped contexts; this packet
adds the distinct sampler's caller guards,cap and tail,not a second claim to
reconstruct that shared helper. No live defect/security finding is asserted.

## Reproduction and validation

Ubuntu24.04/WSL2,Python3.12.3,GNU binutils2.42,default AT&T.

```text
make doctor verify test catalogue-check reproduce
python3 tools/latency_sample_static.py
python3 tools/latency_sample_static.py --output work/repeat
diff -ru work/latency-94 work/repeat
```

Full size/digest verification precedes the collector's local controls. Retained
exports contain raw disassembly,exact FDE,actual RELA rows,range/literal/control
hash records. Six tests cover six instruction-range corruptions,two literal
corruptions,five RELA retargets,decoded independent guard destinations,all tail
stores,and an explicitly local MINSD architectural model including infinity
and NaN. Models never invoke the target or prove live value reachability.

Required checks passed: 437 tests in 151.783 seconds. Four producer exports match an
author repeat byte-for-byte;not independent peer review. Eight identities,
three signatures,37imports and seven pins verify unchanged. Analysis ready,
exact rebuild unavailable. Logs mask local checkout/tool prefixes and normalize
CRLF toLF;raw instruction/frame/relocation exports unchanged.
No input/pin/generated-progress/gate change,captured target/emulator execution,
Rust implementation/build,runtime equivalence or hostedCI claim.
Next close the measurement helper and clock/input ABI before claiming units,
finite-input invariants or reconstructing this sampler.
