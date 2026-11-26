# RE-009: snapshot inline tree entry cleanup

The inline cleanup callee from #7176 requests a cursor result from 0x2442070. A zero first result word exits immediately. For a nonzero result base and valid returned index i, it checks the size word at base+8+24*i and conditionally passes the pointer at the next word to the shared cleanup slot. Independently, it passes base+0x110+72*i to the value cleanup helper 0x2428930, then requests the next cursor result with the original descriptor. This connects the selected inline storage teardown to the previously observed 24-byte key and 72-byte value arrays without assigning semantics to cursor states that the callee has not established.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-inline-tree-cleanup/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
