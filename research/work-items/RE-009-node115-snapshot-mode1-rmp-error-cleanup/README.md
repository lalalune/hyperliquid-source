# RE-009: snapshot mode-1 rmp result cleanup

The mode-1 rmp serialization route in #7148 sends a nonsuccess result to 0x26a5db3. It saves the two following result words before any cleanup call. The writer buffer first word gates release, with the pointer passed only on the nonzero arm. Both arms then place the original three result words contiguously and call 0x26a6bc0 before exiting rather than entering the normal output handoff. This covers the failure-side ownership and ordering contract for the selected mode-1 callback; the result converter internals and the meaning of individual error variants remain open.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-mode1-rmp-error-cleanup/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
