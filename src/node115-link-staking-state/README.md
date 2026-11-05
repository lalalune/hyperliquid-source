# Node115 link-staking logical state

This independently authored, dependency-free Rust package implements the complete
normal logical request/finalize state transition selected by native wrapper
0x58c07d0. Its own typed inputs use 20-byte keys and the three stable row forms
written by the observed native path. BTreeMap/BTreeSet are our representations,
not a claimed reconstruction of the captured containers or dependency graph.

A request checks stake-key membership before equal-key and relationship errors.
A finalize checks the pending peer then the other relationship, without a stake
prerequisite or an added equal-key rejection. All guards use the pre-write state.
It then records and applies the two observed upserts in order, including when
both keys alias. Repeated requests can replace a pending peer.

The comparison covers the complete resulting key/value map, ordered writes,
ordinary error identity and active result discriminants. Its 274 expectations
were frozen before this Rust source. They are independent mathematical values
derived from static native branches, not captured runtime output. See
research/work-items/RE-010-link-staking-state-115 for evidence and limitations.

No captured execution/emulation, full parent admission/signature/wire path,
native ABI/container equivalence, allocation/panic behavior, full-node build
or acceptance gate is claimed.

    cargo test --offline --locked --manifest-path src/node115-link-staking-state/Cargo.toml

Cargo.lock is generated offline for this real isolated component. No original
workspace or missing dependency version is invented.
