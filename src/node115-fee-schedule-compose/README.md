# Node #115 fee schedule composition

This independently authored offline Rust library composes the selected
normal-return fee schedule gates mapped by PRs #2153, #2162, #2169 and #2176.
Inputs model the observed tier, secondary, stake-pair, scalar and extra-value
fields; names in this API are descriptive, not recovered source types. The
caller supplies the result of the two floor-helper invocations. The callback
is invoked in the measured order only when earlier gates admit the input.
`Passed` means the modeled gates pass under those supplied results; it is not
proof that native floor calculations pass, a fee was calculated or a ledger
was updated.

The relation assumes valid stable inputs, normal return and preservation by
the allocation/iterator helpers, and binary64 round-to-nearest ties-to-even
with masked exceptions and DAZ/FTZ disabled. It aggregates rejections and does
not reproduce native diagnostics, exception handling, allocator behavior,
original ABI, financial units or storage semantics. The extra values supplied
must be the values at record offset +24 in the native iterator's visitation
order (helpers 0x37c7260 / 0x4504fe0); the API does not determine that order. Callback behavior must match
the two native calls and must not alter the stable input or FP environment.
It does not run captured code, connect to a node or operate on real funds.

Run `cargo test --offline` and `cargo test --offline --release` in this
directory. The evidence packet documents the target, proof boundaries,
commands, controls and unclosed component gates.
