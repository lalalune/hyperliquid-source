# RE-009: snapshot ring cleanup landing paths

The ring cleanup helper in #7168 and #7169 contains two visible landing paths. The one at 0x24ff1bc converts the saved first-span offset to an absolute pointer, drains pending 96-byte records through 0x24ac6c0, then hands the saved second-span base and count to 0x24ad150. The other landing block at 0x24ff198 drains the pending record cursor in the second span without that extra handoff. Both preserve the incoming exception object and reach the same resume call. These are observed landing block entry contracts. This does not assert which particular calls enter the blocks without exception table analysis.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-ring-drop-landing/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
