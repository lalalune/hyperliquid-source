# RE-009: snapshot cleanup cursor sibling geometry

The adjacent cursor body at 0x2442420 uses different node geometry from the cursor in #7181 through #7183. The candidate key count lives at +0x4ae, the saved child position at +0x4ac, and the selected child slot after index i at node+0x4b8+8*i. The leftmost descent uses +0x4b0. The parent ascent prepares candidate release sizes 0x4b0 and 0x510. These offsets distinguish the two cursor bodies for reconstruction and prevent reusing the previously validated layout for this sibling. This is a bounded operand map without a claim about the sibling call graph.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-cursor-sibling-geometry/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
