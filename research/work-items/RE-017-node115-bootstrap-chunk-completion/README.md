# RE-017: Bootstrap chunk advance and final receive-baseline check

Prior [bootstrap range evidence](../RE-014-bootstrap-range-rust-115/README.md)
covers the initial inclusive arithmetic. The
[query descriptor proof](https://github.com/lalalune/hyperliquid-source/pull/7277)
and [received-row handoff](https://github.com/lalalune/hyperliquid-source/pull/7281)
connect the first request and selected response to the replay worker.

When the row cursor reaches its end, the comparison at `0x5a82cd5` takes
`0x5a82e0f`. On the selected ordinary continuation the code loads the
old chunk end from F+0x290, computes its saturating successor, writes it
to F+0x288 as the next lower word and clears F+0x2c8. If the new lower
word is no greater than the saved target at F+0x280, it reuses the
established inclusive chunk builder. Otherwise the finish path reloads
the current Block receive baseline from the retained replay owner.
An empty buffer uses the owner field +0x110. A populated buffer uses
the latest 16-byte row's Block and its saturating successor.

The final comparison at `0x5a88433` checks that freshly obtained word
against the saved target. Equality reaches the `finished bootstrap`
diagnostic and selected tag 0x44. The other edge formats a separate
result and reaches tag 0x2e. Exhausting requested chunks therefore
does not by itself establish the normal completed outcome. This result
uses normal valid objects and does not reconstruct scheduling, real
checkpoint provenance or state-root validation.

```sh
python3 -B research/work-items/RE-017-node115-bootstrap-chunk-completion/verify.py
```

[Raw offline output](offline-log.txt) and [instruction windows](windows.txt).
