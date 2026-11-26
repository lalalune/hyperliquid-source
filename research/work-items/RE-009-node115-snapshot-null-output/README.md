# RE-009: snapshot null output fast path

The two output helpers selected by the snapshot worker mode both compare the output byte slice against exactly nine bytes, /dev/null. Their eight-byte compares and ninth-byte checks converge on a zero return and direct epilogue when all bytes match. Other lengths or unequal bytes take the normal path logic. Thus the literal request suppresses the selected helpers before their path processing rather than relying on an operating-system write to the null device. This establishes helper-local behavior. Snapshot construction before those calls and the behavior of other paths remain outside scope.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-null-output/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
