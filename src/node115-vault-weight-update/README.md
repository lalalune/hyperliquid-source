# Selected vault-weight writeback

This owned logical model starts at the normal snapshot continuation of node #115 `0x44ad9e0`. It snapshots each key's current ratio, adds the supplied delta to a target key, applies the observed floating guards and writes back while preserving occupied value tails. The positive-delta prepass and the native allocator, diagnostic and container internals are explicit boundaries. The map supplied to the continuation must reflect any effects of that prior prepass. The evidence and exact limits are in `research/work-items/RE-001-node115-vault-weight-update`.
