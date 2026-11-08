# Node 115 set-referrer state

Independent `no_std` Rust with real code, user, referrer and history maps.
`set_referrer` implements the selected core's ordered gates, user creation,
quota bucket refresh/debit, history insertion/replacement and final assignment.
The owned calendar input uses the existing daycount/date implementation.

The [evidence packet](../../research/work-items/RE-010-node115-set-referrer-source/README.md)
records target identity, exact ordering, reference cases and boundaries.
Outer request decoding, code normalization and authorization are excluded.

Run `cargo test --offline --locked --manifest-path src/node115-set-referrer/Cargo.toml`.
