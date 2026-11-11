# Node115 named-agent erase state

Independent owned Rust implementation of the logical action at `0x3be79a0..0x3be7e79`. It accepts actual owner keys, ordered agent records, a name string and a validated time. It creates an absent owner's empty record even when returning `0x5c` for no match, removes only the first exact UTF-8 byte match, preserves remaining order and opaque fields, and replaces the owner's entire follow-up set with a singleton containing the removed agent address and computed time. Success is `0x1a2`.

The native duration constant is **6.0 seconds**, not days. The source closes the selected duration/time/calendar helper path: add six seconds, consume any native leap-nanosecond extension, carry the date, and select the original maximum timestamp on date overflow. `Moment::new` validates dates through the existing `node115-daycount-date` source and checks the native time projection. Leap nanoseconds in `[1e9,2e9)` are valid only at second 59 of a minute. No external calendar result or caller-supplied decision is accepted.

`State::agents` represents the owner map at native state `+0x48`; `followups` represents `+0x120`. Agent rows retain their unobserved 12 bytes at `+0x18` without assigning meaning. The copied agent key is the full 20 bytes at `+0x24`. Follow-ups are a set of address/time records, not an append-only queue; a successful erase discards the owner's previous set. This detail is backed by both singleton construction and replacement-helper writes.

This is bounded agent-state progress related to #3914, whose broader nonce/replay path remains open. Prior #2283 contains the corresponding static evidence. No outer authorization, signing, full nonce replay, physical collection layout or live behavior is claimed. Valid native Strings/collections and successful allocations are premises. Malformed sentinel pointers, panics, destructor failure and allocator behavior are excluded; no captured code is run or emulated.

Four tests pass in debug/release, including 4,000 actions from 100 independently generated Python list/dict scenarios: 1,300 removals and 2,700 no-match results. Tests compare complete projected state and cover missing owners, duplicate names, exact Unicode/null bytes, owner-key tails, replacement rather than append, retained order/opaque bytes, day boundaries, native leap nanoseconds and maximum-date fallback. Fixture SHA-256: `53e8fc6889aa8a65b5123d2c6f6bf1a3acdb1c8dc950b98134a420c2e59d540d`.

```sh
python3 src/node115-agent-erase-state/tests/reference.py
cargo test --offline --manifest-path src/node115-agent-erase-state/Cargo.toml
cargo test --release --offline --manifest-path src/node115-agent-erase-state/Cargo.toml
cargo clippy --offline --manifest-path src/node115-agent-erase-state/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node115-agent-erase-state/Cargo.toml -- --check
python3 research/work-items/RE-001-node115-agent-erase-source/verify.py
```

The static verifier uses Capstone 5.0.7 and the original pinned target. See the evidence packet for the exact instruction/data closure and limitations.
