# RE-009 snapshot cleanup helper comparison

The parent-body comparison in #7184 identifies three differing call destinations, 0x242a760 and 0x24ab350. The normal path in the first destination was separately mapped by #7185. This packet checks both complete 202-byte FDE spans in the #115 ELF. All 178 bytes outside six 4-byte displacement fields match. Each paired field resolves to the same destination, including the two calls to nested record cleanup, the two release-slot references, the unwind-resume call and the final indirect call.

Together with the parent comparison, this removes the three direct-call destination differences at one call level. The result compares bounded instruction extents and addresses. It leaves exception-table coverage and runtime behavior open. The original instructions are never executed.

Run the verifier in the offline log from the repository root. The included unwind records give the two span boundaries. The verifier authenticates the ELF and rejects mutations to each displacement and one unmasked opcode in both bodies.
