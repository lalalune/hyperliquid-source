# node115 mid-price market-order builder

This standalone Rust crate models the six market-order builder copies documented
in `research/work-items/RE-014-mid-market-order-builder-115`. It is pinned in
code to node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The model includes market/asset/decimal early exits, overflow-safe midpoint,
copy-specific price factors and record constants, tick rounding, packed time
conversion, and the observable 0xe0-byte record layout. It does not model the
book reader, insert routine, surrounding state, or external side effects.

Run `cargo test --manifest-path src/node115-mid-market-order-builder/Cargo.toml`
from the repository root. The test consumes the committed `builder_cases.tsv`
from RE-014 and checks each row's outcome class and limit (6,810 rows). The
packet's target comparison reports 6,810/6,810 matching builder runs, but its
TSV does not contain each run's full record bytes. Consequently, this crate's
test validates the saved output and documented record fields; it does not
independently compare all record bytes against the target. The node binary is
never executed.
