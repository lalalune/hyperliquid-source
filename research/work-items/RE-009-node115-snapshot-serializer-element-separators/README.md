# RE-009: snapshot nested array element separators

The nested snapshot serializer emits a delimiter before each available record. Its first-element flag selects newline alone, while subsequent records take the comma-plus-newline branch. With sufficient capacity both paths advance the writer length by their exact delimiter width before loading the next record formatting state. The two reserve guards distinguish the one-byte and two-byte requirements. This is the inner array in 0x258ba80, distinct from the enclosing mode-1 array framing documented by #7149 and #7150. The record encoder is outside this packet.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-serializer-element-separators/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
