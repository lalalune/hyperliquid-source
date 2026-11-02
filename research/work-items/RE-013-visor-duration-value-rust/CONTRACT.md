# Complete supplied binary64 duration value — pre-source contract

Target Visor SHA256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`, source base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The complete outer body is `0x330360..0x330581`, with its sole helper `0x7a6530..0x7a65a1`. All ends are exclusive linked ELF VAs. This closes the general value conversion explicitly excluded by the earlier fixed1/fixed60 proofs; their captured evidence receives full credit and zero additional recovery credit.

Every u64 input is interpreted as a raw binary64 encoding in low XMM0. Under the native memory/call/ISA premises in `PROOF.md`, the result is the full RAX seconds word and zero-extended EDX nanoseconds word. Let x be the exact real value for finite input:

1. Negative values, both zeros, infinities and NaNs return `(0,0)`.
2. For `0<x<2^64`, round the exact real `x*1,000,000,000` to the nearest integer with ties to even, then divide into seconds and a remainder below one billion.
3. For positive finite `x>=2^64`, round `x*1,000,000` to binary64 under the admitted ISA rounding. A finite product returns `(18446744073709,551615000)`; an infinite product returns `(0,0)`.

This deliberately preserves the nonmonotone large-input behavior. It is not a usual saturating seconds conversion, an abstract decimal duration parser, or a sleep policy. Raw input `43efffffffffffff` returns `(18446744073709549568,0)`; `43f0000000000000` returns the much smaller pair in rule3. The first positive scaled-overflow input is `7eb0c6f7a0b5ed8d`, with a strictly finite-product predecessor. These consequences require the arithmetic proof; no observed execution is claimed.

The provisionally distinct future component is `src/visor-duration-value`, a real dependency-free standalone crate, with no root workspace or dependency on unmerged readiness source. Planned API: `convert_bits(u64) -> DurationValue`, with private seconds/nanoseconds fields and `seconds() -> u64`, `nanoseconds() -> u32` accessors. Those names/type/ABI are new safe API choices. Every raw input is accepted, and each result is canonical; there is no invented refusal policy. No clock, process, filesystem, network, allocator or floating environment is accessed by the operation.

Native correspondence assumes normal x86-64 SSE2 operations, round-to-nearest-even, DAZ/FTZ off and masked relevant floating exceptions. Those are explicit prerequisites, not observations of a deployed CPU or MXCSR. Exception flags, traps, asynchronous transfers, other registers/upper SIMD lanes, original source types and compiled-target identity remain outside the value API. Valid immutable literal/call storage and a valid disjoint stack/return frame remain necessary.

The pre-source oracle uses exact rational values and distances to neighboring integer nanoseconds. Future production is planned to use bounded integer significand arithmetic, with an independently proved raw-bit overflow boundary. It must not import the oracle, expected values, case labels or IDs. `PROTOCOL.md` fixes an input-only client boundary. Source and client remain absent until the coordinator and independent peer admit a frozen proof/corpus; a later source/build gate must precede compilation.
