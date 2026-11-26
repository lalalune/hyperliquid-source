# RE-009: snapshot inline storage cleanup handoff

The storage sentinel branch excluded by #7167 takes the descriptor word at stack +0x18 as its presence test. A nonzero word copies the next two fields into two local groups and sets both presence words to one. It carries the source word at stack +0x28 into descriptor +0x40. For a zero presence word the branch sets both flags and the final word to zero. Both paths pass the constructed descriptor at stack +0x50 to 0x24832e0. This maps the exact alternative handoff to cleanup and leaves the callee implementation outside scope.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-inline-storage-cleanup/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
