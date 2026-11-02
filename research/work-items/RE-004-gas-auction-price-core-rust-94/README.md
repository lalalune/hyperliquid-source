# RE-004: Rust for the post-round node94 auction-price core

Component: quantities/rounding and gas-auction pricing, conditional scalar suffix.
Target node94 SHA2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
91774280bytes. Basee5c9b6436876b2a4a39daef813171f9879317699.
Credit the unchanged RE-004-gas-auction-price-94 packet and original source
commit5c35577e. Its actual-instruction analysis establishes arithmetic but
supplies no independently built Rust price component. Freeze30465019 and
additional boundary smoke5093a1fd precede production Rust.

## Scope and observed relation

Original ELF FDE0x325ccb0..0x325cf3c,652bytes/149instructions, complete body
SHA25631f59020bd58fc5bd04f7a89b2be59a84bdf6dd701284ef86439b36e65da1a51.
Full original exports, data/source/call bindings and prior negative results
remain unchanged. This comparison starts at0x325cd8b, **after** the existing
round helper returns, and stops at0x325cccd after the common result-tag store.
It visits92selected instructions. It does not reconstruct all149instructions,
execute a clock/seconds/round function, or claim whole-auction behavior.

Explicit inputs are the returned binary64 bit word, bucket u64, start and
floor u64. The qualified suffix observes:

1. Nonfinite rounded values (including both infinities) become elapsed0;
   nonpositive values also0. Finite positive values truncate, capped atMAX.
2. start<floor selects raw tag0xbf and leaves the output price field untouched.
3. Otherwise factor=max(1.0 - f64(elapsed)/f64(bucket),0.0). The integer
   subtraction happens **before** converting span=start-floor to binary64.
4. The product is converted with the same target saturation rule. Adding
   floor uses wrapping-detected fallback to floor, not saturation atMAX.
5. Success writes raw tag0x186 and the calculated price.

The Rust result is an own Result<u64,StartBelowFloor> projection. Neither its
layout nor a synthetic output poison is asserted to be the original ABI.
The input is an opaque already-rounded word: original helper reachability,
calendar fields/units and error ordering before this suffix remain unclosed.
Normal round-to-nearest, denormal-preserving binary64 value semantics are
assumed. Quiet NaNs are included; signalling NaNs, exception/status flags,
nondefault FP control modes and cross-ISA exception behavior are excluded.
No FMA or reassociation is used in the independently authored Rust expression.

Selected constants are read from the authenticated original .rodata, not
replaced by callback values. The new Engine creates a plain Machine with
empty calls/slots/statics; it does not construct the older Harness with its
helper substitutions. Calls/returns are forbidden, PC ranges bounded, and
writes restricted to the16-byte synthetic output. Auction input64bytes is
read-only during evaluation. No fake target slot, callee, allocator or helper
is introduced. This is explicitly authorized offline Python instruction
evaluation; no native captured process, Unicorn, real clock/IO/network,
wallet/signature or chain action occurs.

## Frozen population, builds and controls

8312distinct four-word inputs:60binary64 words *10buckets *13start/floor pairs
plus512unique public deterministic vectors. FP words cover signed zero,
subnormals, finite extremes, infinities/quiet NaNs and neighboring encodings
around1/2^53/2^63/2^64 and ordinary elapsed points. Integer boundaries include
bucket0,MAX, high floors, start<floor and equal values. FREEZE pins full input
and output SHA256s before compilation; long corpora/products regenerate
outside Git. Independent scalar equations agree with each actual route.

Thirteen frozen smoke rows cover equal/start-below-floor, precision loss,
nonfinite input and wrapped addition. Two actual native Jcc changes alter
the subtraction guard and wrapped-add fallback. owner.json binds the complete
body and all selected raw instruction partitions through Capstone5.0.6.

Real rustc1.94.1(e408947bfd200af42db322daf0fadfe7e26d3bd1), LLVM21.1.8, builds
standalone no_std rlibs at opt0/opt3 with overflow checks and codegen-units1.
Separately linked input-only clients each match all8312outcomes. Actual compiled
smoke passes. Three compiled mutants change infinity handling, overflow fallback
and subtract-before-rounding order:63/310/451mismatches, all smokeexit101.
Own opt3 archives rebuild raw-identically. Buildexit0 in87.853wall seconds;
freezeexit0 in23.002wall seconds. This host macOS arm64 reproducibility is
not original Linux x86-64 byte identity or a source/compiler provenance match.

Five focused tests PASS29.399wall seconds, pinned rustfmt and Clippy library/
test PASS, fresh catalogue-check PASS. Combined command completed exit0 in
78.196wall seconds; nonfatal xcrun cache warnings are retained. Outcomes are
recorded in validation-results.json. No new Cargo workspace, invented dependency/lockfile,
transplanted bytes or inferred unlicensed reference implementation is used.
The old Python producer has no Rust comparison; the component runner supplies
only the bridge needed to compare this new price source against frozen actual
instructions, then runs compiled controls. Shared modules remain unchanged.

## Reproduce

From repository root with authenticated inputs, Python3.12.14, Capstone5.0.6
and actual pinned1.94.1 Rust tools:

    python3 tools/gas_auction_price_core_rust.py --rustc "$RUSTC" --output /new/output
    python3 -m unittest tests.test_gas_auction_price_core_rust -v
    "$RUSTFMT" --check --edition 2021 src/node94-gas-auction-price-core/lib.rs src/node94-gas-auction-price-core/input_only_driver.rs
    "$CLIPPY" --edition=2021 --crate-type lib src/node94-gas-auction-price-core/lib.rs --emit=metadata -o /new/lib.rmeta -D warnings
    "$CLIPPY" --edition=2021 --test src/node94-gas-auction-price-core/lib.rs --emit=metadata -o /new/test.rmeta -D warnings
    make doctor verify test catalogue-check reproduce

Output must be new. Capture identity, frozen corpus hashes, owner/control records
and both smoke copies are checked before compiler admission. build-result.json
records actual commands/source/output/compiler identities, replacing private
path spellings only; no operand/output normalization. Shared signed-input,
import and inventory checks reuse completed#1831 only within explicitly
unchanged paths in shared-input-validation.json; this is not new-code verification.
Full make test has not completed and awaits upstreamCI; queued is not PASS.

Resource policy is serial10%active wall-time duty with bounded commands;
setpriority is unavailable. This is not a guarantee of exact aggregateCPU use.
No parallel build/agent or duplicate checkout is used. Full component gates,
byte-credit registry and catalogue inputs remain unchanged. Ownership, complete
auction lifecycle, timing/helper closure, original ABI and whole-node behavior
remain open. Next close the bucket-start and elapsed helper bodies before
joining this source to the full price entry.
