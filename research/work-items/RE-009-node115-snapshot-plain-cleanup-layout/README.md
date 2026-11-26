# RE-009: snapshot nonsentinel cleanup allocation layout

The nonsentinel path in the nested cleanup selects allocation-size, base and live count from distinct words. After consuming its first vector it uses the initial word to size the release. The second vector reads allocation magnitude at +0x18 and base/count at +0x20/+0x28. After the second vector it enters a third vector with +0x30/+0x38/+0x40, which is absent from the sentinel layout described in #7173. All selected releases pass size times 200, and the third cleanup loop iterates count times before its release. This proves the additional ownership layout needed for the nonsentinel branch and leaves exception behavior open.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-plain-cleanup-layout/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
