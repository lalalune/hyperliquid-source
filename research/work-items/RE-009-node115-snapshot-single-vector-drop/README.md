# RE-009: snapshot single vector cleanup

The helper called from the inline value cleanup body at 0x2428c3a consumes one vector descriptor. It takes the owned size, base and live count from offsets 0, 8 and 16. The normal loop advances 200 bytes per live record and selects the nested argument at record +8 for a nonzero first word or +0x20 otherwise. After all live records, it passes the base and 200 times the allocation-size word to the release slot only when that word is nonzero. This resolves the previously unexamined helper contract from #7184. The sibling helper and exceptional control flow are outside scope.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-single-vector-drop/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
