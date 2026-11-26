# RE-009: snapshot inline cursor first leaf initialization

The live tag-one cursor helper takes its initialization route when the current-node word at +8 is zero. The route reads root and depth from +0x10 and +0x18. For a valid tree it descends through child pointer +0x430, handling depth modulo eight before advancing in groups of eight. It then publishes the leaf as the current node, clears the depth and position words, and enters the normal key-count test with index zero. This describes initialization before #7181’s parent ascent path, and excludes invalid tree pointers.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-inline-cursor-initialize/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
