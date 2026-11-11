# Node #115 execution publication: replacement then queue send

Partial HL115-023 / RE-008, node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. [#2096](https://github.com/lalalune/hyperliquid-source/pull/2096) identifies the two downstream consumers, and open [#4901](https://github.com/lalalune/hyperliquid-source/pull/4901) implements the compact five-byte projection. This contribution resolves selected effects inside those consumers without duplicating either producer. It does not claim complete concurrent publication or persistence to disk.

## Compact publication

At `0x2af766e`, the parent reads context+0x38f8 and appends that opaque u64 to the three-word compact vector descriptor. It calls `0x2502370` with object+0x2c8's pointee+0x10 and that descriptor, then separately calls `0x2cedc50` with object+0x2a0 and all 176 bytes of the producer result. The argument called a key in some internal locking code is the location metadata for execution_state.rs line153; no account-key meaning is claimed.

`0x2502370` allocates 48 bytes: strong and weak counts start at one, followed by the exact 32-byte descriptor. It passes a capture containing the original publication owner and new allocation to `0x29dd5e0`. With that wrapper's lock-order-diagnostic byte+0x20 clear, it tail-calls `0x2a35190`. After successful lock acquisition and clock helpers, that function swaps owner+8 to the new allocation, releases the lock, and returns the old pointer. The caller decrements the old strong count. Last-strong destruction `0x5a8baa0` releases capacity*5 backing bytes, decrements weak count and, when last weak, releases the 48-byte allocation. Aliases therefore keep the old data alive; empty new vectors still replace publication. Timing hooks, clock failures, lock contention and unwind paths are outside this normal-path relation.

The Rust source uses an owned vector of five-byte records plus the context word behind `Arc`. This models normal logical ownership, not native allocation layout or lock implementation. Projection source and its meaning remain prior-work/input contracts.

## Separate full-result send

`0x2cedc50` increments handle+0x10 before testing owner+0x1c0. On its selected open path, state increases by two, a ticket is reserved from owner+0x88, and `0x2cd0390` locates the segment for `ticket & ~31`. The slot is `ticket & 31`: all 176 bytes are written before bit `1 << slot` is published at segment+0x1610.

The segment helper follows +0x1608 links, allocating 0x1620-byte segments with base increased by32 and zeroed next/readiness/retirement fields when missing. On the no-contention path, an eligible fully published prior segment can be removed from the producer-head pointer; it records the current ticket counter at +0x1618 and sets readiness bit32. Eligibility compares the initial segment distance with the ticket's low five bits. The source retains retired segments for inspection; receiver-side reclamation is not established.

After the row is published, wake state owner+0x110 is ORed with2. A previously nonzero state leaves the registered waker untouched. Previously zero state takes/clears the waker and resets state to zero; a nonnull waker reaches its function+8. The source stops immediately before this callback, with the row and state changes visible. Normal completion returns AL=5.

If the closed bit was already set, no ticket or row is published. A first record word of exactly 0x8000000000000000 returns5 without decrementing the initial handle increment; otherwise the function reaches the record destructor before its later decrement/return0. The source stops before that opaque destructor. Open state 0xfffffffffffffffe reaches a fatal boundary after the initial handle increment. These boundaries preserve the earlier compact replacement; no rollback is invented. Complete cleanup, arbitrary pointer-bearing payload ownership, scheduler/waker behavior and interleaving correctness remain open.

## Validation

`python3 research/work-items/RE-008-node115-execution-publication/verify.py --target <pinned-node-115>` checks seven windows, 1,977 original bytes / 468 instructions, actual calls/imports and 35 semantic corruption controls. `cargo test --manifest-path src/node115-execution-publication/Cargo.toml` and `--release` run six tests: distinct payloads, alias survival/last release, empty replacement, closed/capacity boundary order, 300 records across ten segments with exact byte/readiness/retirement checks, and all four low wake states. Formatting and strict Clippy pass.

No captured instructions execute or are emulated. Valid initialized owners, successful allocation and lock/time helpers, no interfering send/receive operations, and a valid nonwrapping segment topology are premises. InvalidLogicalState is a source guard, not a native return. These are bounded static/source relations; full component gates remain false.
