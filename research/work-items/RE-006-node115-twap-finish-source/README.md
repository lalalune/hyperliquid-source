# Selected prechecked TWAP finish source

`src/node115-twap-finish` supplies a logical owned tracker for the selected
precheck-passed take and finish handoff. It removes the requested order, removes
the user only if its order map becomes empty, selects the tag-1 spot or perpetual
status builder, and, after that builder returns, constructs the logical tag-4
event fields. The perpetual path divides the first order-body word by 10,000 and
stops before the native expect-failure if the index is outside the market count;
the order has already been removed at that boundary.

The source takes valid live 0x68-byte bodies through `StoredBody::new`; its
rejection of byte +0x22 equal to 2 is a host input guard, not a native insertion
rule. `prepare` starts after a successful native precheck (result byte 2). A
missing user or order maps to the native 0xd4 take error; existing tracker data
is unchanged. Alternate precheck results, builder implementations, allocator and
raw pointer ABI, native panic and unwind, and event inactive tail are excluded.
`complete` receives the 0x78-byte status after a normally returning builder; it
models the logical event and owns the reason bytes without claiming the native
string descriptor layout. `node115-twap-advance` does not expose the full raw
order body, so this crate does not claim to implement its handoff or invent a
parallel-map identity invariant.

Prior [#4329](https://github.com/lalalune/hyperliquid-source/pull/4329),
`RE-006-twap-finish-115`, established the complete take/finish bodies and their
status-builder boundary. [#4264](https://github.com/lalalune/hyperliquid-source/pull/4264)
established the separate advance path. This source is a bounded independently
authored implementation of the selected contract, not a claim of new ownership
of those bodies or full TWAP behavior. The prior packet's observed cases include
both route families, missing users/orders, empty-user removal, market bounds and
status/event paths; its callee contracts and interpreter inputs remain prior
work and were not executed here.

Target node #115: 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`records.json` retains four cited-only full FDEs (5a10250, 5a10560,
5a17dd0, 5a18550) with exact instruction transcripts; `verify.py` checks the
target digest, FDEs, 650 decoded instructions and 12 selected witnesses.
The transcript mutation controls test evidence consistency, not runtime
behavior or independent proof of the complete contract. No captured executable
was run or emulated. The source tests cover absence without mutation, neighboring
users, sentinel rejection, successful spot/perp selection, event fields, and
the market stop after removal.

```sh
PYTHONPATH=/path/to/capstone-and-pyelftools python3 research/work-items/RE-006-node115-twap-finish-source/verify.py --target artifacts/node/115/hl-node
cargo test --manifest-path src/node115-twap-finish/Cargo.toml
```
