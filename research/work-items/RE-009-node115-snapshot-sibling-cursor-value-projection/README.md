# RE-009: snapshot sibling cursor value projection

The caller at 0x2481c40 consumes the alternate cleanup cursor at 0x2442420. Both the initial cursor call and the next-entry call write the same stack result. A zero first word ends iteration. Otherwise the caller takes the result index at +0x10, multiplies it by 88, and passes base + 8 + 88*i to 0x243a250. Unlike the separately observed 24-byte key and 72-byte value slots in #7178, this caller uses one 88-byte stride and one cleanup call. This binds the alternate geometry to a concrete value layout under valid cursor results. The record fields and runtime behavior are outside the claim.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-sibling-cursor-value-projection/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
