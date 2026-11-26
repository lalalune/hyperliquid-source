# RE-009: snapshot recursive order cleanup

The cleanup helper reached by the 200-byte order cleanup loop processes two independent pointer-and-size pairs, at +0/+8 and +0x18/+0x20. Each nonzero size selects the shared cleanup slot. Its next child collection uses base at +0x38 and count at +0x40. For a valid descriptor with representable count plus one, it invokes the same helper once per 168-byte child and only then conditionally calls the shared release slot with the child base and 168 times the separate word at +0x30. This establishes recursive traversal and release ordering for the selected normal prefix. The remaining suffix and unwind paths are outside the packet.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-order-recursive-drop/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
