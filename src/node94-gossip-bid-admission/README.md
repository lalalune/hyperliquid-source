# Node #94 gossipPriorityBid admission

Independently authored dependency-free `no_std` Rust for the wrapper gates that
`research/work-items/RE-010-gossip-priority-bid-path-94` recovers at `0x1e60bb0` of
node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No inferred reference code is copied.

```rust
pub fn admit(bid: &Bid<'_>) -> Result<Admitted, Refusal>;
```

Gates run in target order: slot, gas, text length, full text parse. `Bid` and `Admitted`
are safe research views, not the original object layout. The handler, its balance rules
and the state mutation stay outside this component. The IPv4 rule restates the merged
`RE-004-gossip-bid-gates-94` result; here it is compared only on the packet's vectors.

The real build is direct `rustc 1.94.1`, edition 2021, with no dependencies or Cargo
package:

```sh
rustc --edition 2021 --test src/node94-gossip-bid-admission/lib.rs -o work/gossip-bid-admission
work/gossip-bid-admission
```

The tests replay all 1,568 packet vectors. This is no compiled-byte comparison, and no
acceptance gate changes.
