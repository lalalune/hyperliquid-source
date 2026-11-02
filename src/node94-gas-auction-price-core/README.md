# Node94 auction-price arithmetic suffix

Independent no_std Rust bound to node94 SHA256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
quote_from_rounded_word takes an explicit already-rounded helper word and three
raw u64 fields. It implements only the post-round price core, not a clock,
complete auction entry/lifecycle or original ABI. Quiet-NaN/ordinary binary64
value semantics are measured; FP exception/control-mode claims are excluded.

Build with actual pinned rustc1.94.1 directly (no Cargo graph is claimed):

    rustc --edition=2021 --crate-name node94_gas_auction_price_core --crate-type rlib lib.rs
    rustc --edition=2021 --test lib.rs -o /new/smoke

From repository root, tools/gas_auction_price_core_rust.py --rustc /pinned/rustc
--output /new/output builds real opt0/opt3 libraries and compares their clients
with frozen actual-instruction outcomes, smoke and three compiled mutants.
See research/work-items/RE-004-gas-auction-price-core-rust-94 for exact scope,
commands, hashes, raw population, observations and unresolved integration.
