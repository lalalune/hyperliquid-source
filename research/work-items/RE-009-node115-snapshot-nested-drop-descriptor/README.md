# RE-009: snapshot nested drop descriptor

The nested cleanup invoked by the snapshot storage loops in #7168 and #7169 branches on whether the first input word equals the signed minimum. The sentinel case reads pointer/count at +0x10/+0x18 and the other case uses +0x08/+0x10. In each normal loop the current outer record advances by 200 bytes and its first word chooses the inner cleanup input. A nonzero value passes record +8 while zero passes record +0x20. Both paths call 0x230af10. This pins the layout needed to walk the nested cleanup records. Allocation ownership after the loops and exceptional control flow remain open.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-nested-drop-descriptor/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
