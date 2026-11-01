# node94 supplied-sample funding rate values

This dependency-free `no_std` crate reconstructs the bounded value relation of
node94 `0x3750610` and the absence-to-positive-zero projection at `0x275eda0`.
It is newly authored MIT Rust, not recovered upstream source text. Captured
artifact SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`funding_rate_bits` borrows optional raw binary64 samples, accepts optional raw
interest and multiplier values plus raw clamp bits, and returns an optional raw
rate. `insertion_bits` changes only absence to positive zero. It does not insert
into a map. Integer arithmetic preserves ordered rounding, signed zero, gradual
underflow and the stated Intel NaN selection without using host floating point.

The corresponding native claim assumes valid selected native memory, explicit
helper frames and Intel SSE round-to-nearest-even with DAZ/FTZ off and masked
exceptions. It does not establish a target CPU/MXCSR setting, arbitrary native
maps, allocations, scheduling, economic units or global settlement. Every valid
borrowed slice has ordinary language storage requirements; synthetic native
length words are outside that correspondence.

The proof, independently frozen exact-rational expectations, protocol and
isolated-build qualification are under
`research/work-items/RE-007-funding-rate-values-94`. This is a real standalone
component; no whole-node build or completion gate is claimed. Production source
is frozen and reviewed before any qualification compilation. Build results are
reported separately in the evidence packet, including failures and raw bytes.
