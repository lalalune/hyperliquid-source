# RE-009: snapshot order row success and stride

The shared child-array serializer passes its current record pointer to 0x22b89c0 along with the saved writer pointer. A nonzero result leaves the direct iteration path before advancing the record pointer. A zero result advances by 200 bytes, sets writer byte +0x20 to one, and compares the resulting pointer with the saved limit. Equality proceeds to array finalization, and inequality returns to the next item loop. This binds the stride and result gate separately from the enclosing field-name and child-pair handoff. The individual record fields remain open.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-order-row-loop/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
