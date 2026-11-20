# RE-005: Node #115 GossipRpcResponse prefix boundary

This packet records the native caller contract that was missing from the
earlier logical response decoders. The complete response owner is the
authenticated FDE `0x5aac7c0..0x5aacc22` in node #115. It invokes the selected
variant readers with the state descriptor in `r14`, then immediately consumes
their result tags and copies result fields into its output object.

The retained body contains no post-success comparison of the descriptor's
remaining-length qword at `+0x18` before the response result is returned. The
observed contract is therefore a **prefix** contract: a child may leave bytes
in the descriptor and the parent still publishes its result. This is a static
control-flow observation, not a claim about transport framing or every caller.

Relevant observations from the full body:

* outer tag 1 calls `0x4de6210` at `0x5aac901`, then stores the returned
  sixteen-byte result and publishes the selected result at `0x5aacc0b`;
* outer tag 2's present arm calls `0x5aabd20` at `0x5aac886`, copies the
  returned fields, and rejoins at `0x5aaca57`;
* nested success calls `0x5824f20` at `0x5aac979`, checks only its result tag
  `0x12`, and stores the returned descriptor fields at `0x5aac98c..0x5aac9b5`;
* the common epilogue begins at `0x5aacc12` and returns the parent output.

No EOF policy is inferred from the logical Rust APIs. In particular, this
packet does not add an exact-frame helper: that would be a caller policy not
established by these bytes. The native ABI, dynamic reachability, allocator,
unwind paths and network framing remain open.

## Reproduction

```sh
python3 research/work-items/RE-005-node115-gossip-response-prefix-boundary/verify.py
make verify
make catalogue-check
```

The verifier authenticates the #115 digest, the complete FDE body hash,
instruction boundaries and the selected calls/branches. It does not execute
or emulate the captured node. No component gate is advanced.
