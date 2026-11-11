# Node #115 scheduled-observer factor model

This Rust model covers the 79-entry binary64 factor table selected by the #115 configuration tag and the observer constructor's post-multiply bit normalizer. The evidence packet is `research/work-items/RE-015-scheduled-observer-115`, bound to node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The packet records 18 table entries of `1.0`, 61 of `5.0`, and the selected normalizer's instruction operands and 13 bit-pattern cases. The Rust API accepts an index only as an analysis-domain lookup (`None` outside 0..79); the native selector has no local bounds check, so `None` is not a claim of native rejection. `observer_value` models binary64 multiplication followed by the recorded normalizer. Tests read the factor-run and normalizer corpora directly from the packet and exhaust sign/exponent/fraction boundary classes.

The tag-to-name association depends on separately established #115 name-classifier evidence. Generic once/callback interleavings, runtime initialization, observer scheduling, native ABI and types, floating-point exception state, nondefault FP modes, downstream effects and whole-component equivalence remain outside this crate. It never runs or emulates the capture.
