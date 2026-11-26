# RE-009: snapshot serializer range rollover

For the tag-2 iterator descriptor used by the selected snapshot serializer, the iteration loop first compares the cursor at local descriptor +8 with its end at +0x10. When the first range is exhausted, it copies the saved second cursor/end pair over the first, and replaces the saved second pair with the exhausted first range. It rechecks equality before yielding a record, so two exhausted ranges skip directly to the termination branch. A nonempty range advances the cursor by 96 bytes and computes the payload address at record +0x18. This is the iteration contract for valid ranges and leaves the element encoder outside scope.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-serializer-range-rollover/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
