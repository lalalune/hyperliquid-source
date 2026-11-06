# RE-009 · Root digest finalization dispatch

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The previous block-root packet resolves the call at 0x41c539a to 0x160bcd0. This packet verifies the finalizer body and its implementation dispatch. The finalizer calls 0x160ab60 to populate a temporary, copies two 16-byte blocks from it into the working state, and takes the selector from temporary stack +0x8a. It ORs bit 3 into the byte at +0x89 before supplying the result to the selected routine. Each selected arm passes a zero counter argument in ECX. Two 16-byte stores copy the resulting working state to the output.

For selector indexes 0, 1, 2, 3 and 4 the selected relative addends are 0x160d200, 0x633d0c0, 0x633fac0, 0x633fac0 and 0x6345bc0 respectively. This establishes four implementations among the five checked entries. It does not prove selector production, valid indexes beyond the examined entries, instruction-set identity, or digest equivalence.

Run python3 research/work-items/RE-009-node115-root-digest-final-dispatch/verify.py from the repository root. Replay checks all 208 bytes and 52 disassembly rows in the FDE, the incoming and preparation edges, five table entries with independent changed-byte controls, and five relative slot bindings.
