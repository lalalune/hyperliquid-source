# RE-017: match replay timer fractional delay rounding

The reconstructed timer converted seconds by multiplying a binary64 by one billion and truncating it. On #115 the selected replay callback loads the delay into XMM0 at `0x515218d` and calls slot `0x64e0f70`, relocated to `0x15ed960`. On the normal, nonnegative finite fractional paths that helper decodes the binary64 fraction and multiplies in integer space. Above-half rounds up, below-half rounds down, and an exact half increments only an odd quotient. A rounded nanosecond field of one billion carries into seconds. The caller combines the returned seconds and nanoseconds and caps the result at `i64::MAX`.

Use Rust's standard duration conversion for the modeled finite nonnegative delays before applying the integer cap. An out-of-range positive value still reaches the model's existing cap, and its invalid-input API still returns None. This is a correction to the selected rounding rule, with the native timestamp representation and the native nonstandard inputs outside this packet.

In the regression, 0.75 ns rounds to one nanosecond and can no longer expire at the insertion timestamp. The test also covers exact half ties in both directions, a carry into the next second and saturation. The packet independently checks the two native paths and computes the expected values from the exact ratios of their binary64 inputs.

Run `python3 -B research/work-items/RE-017-node115-replay-delay-rounding/verify.py` and `cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml` from the root. The [offline log](offline-log.txt) shows the failing regression against the starting implementation and the passing suite after the fix. No captured instructions were executed.
