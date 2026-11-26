# RE-009: snapshot book pair first child handoff

At the selected book_orders serializer, the first nested child is dispatched from the original pair pointer to 0x255da10. Its nonzero result bypasses the following delimiter. On zero return the caller marks its writer, checks for two bytes of spare capacity, advances the pair pointer by 24 bytes and appends comma and newline on the direct path. This establishes the first child to second-child pointer transition and its failure gate, complementing the outer field-name layout in #7159. The record fields and serializer internals remain out of scope.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-book-pair-first/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
