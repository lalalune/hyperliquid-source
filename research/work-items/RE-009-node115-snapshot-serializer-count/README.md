# RE-009: snapshot serializer range count

The serializer called by both selected output helpers first copies the 72-byte iterator descriptor. A first word of 2 selects a count computed from two pointer spans. For valid nonnegative spans at whole-record boundaries, it divides each byte distance by 96 by shifting five bits and multiplying by the modular inverse of three, then adds the counts. Other first words take the count directly from descriptor +0x40. The common path uses the combined value for its empty check. This resolves the consumer side of #7152 without claiming the element encoding.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-serializer-count/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
