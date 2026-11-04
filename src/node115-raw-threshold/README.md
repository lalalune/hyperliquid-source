# Node115 conditional threshold arithmetic

Dependency-free no_std value API for three independently seeded program points.
enter checks unsigned sum overflow before B>bound. after_sum_diagnostic takes
fresh post-point state and saturates its sum. after_secondary_diagnostic takes
a fresh retained sum. No opaque handler is called, simulated or promised to
return; these APIs are not a composed original function or its Rust ABI.

The raw quotient equals floor(sum/500000000) for allu64 by the captured-literal
proof. Threshold is min(q,4000)+1000; raw head changes on strictly lower level.
The three observed words are a measurement view, not an original result type.
Units, caller reachability, aggregates, initialization and hook effects remain
unresolved. See RE-014-raw-threshold-115 for target SHA, bounds, actualcontrols,
pre-Rust freeze and direct rustc1.94.1/edition2021 build. New code is MIT.
