# RE-009 · Root-history post-insert selection walk

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The existing root-tree packet supplies the insert call context. After normal return from 0x4dd45c0, the wrapper reads the history count at +0x18 and exits for unsigned count below 51. For a count at least 51 it builds an iterator based on the representation word. The selected flat advance helper subtracts 40 from its end pointer and returns the resulting row address. The helper's non-flat arm transfers to 0x514dc20.

After an initial representation-dependent walk, the checked straight-line stage makes up to 43 calls to 0x4e2a530. A zero return at any of these 43 sites goes to the wrapper epilogue. Only a nonzero result at every site reaches the qword load through the last returned pointer and the call to 0x4de5ad0, with a pointer to that copied word as its third argument. This establishes the threshold, the success gate and the key supplied to the removal boundary. It leaves the complete logical rank, removal effects, possible count after removal and persistence open.

Run python3 research/work-items/RE-009-node115-root-history-retention-walk/verify.py from the repository root. The verifier checks the artifact, FDE, threshold, all 43 advance/exit pairs, final key projection, selected iterator dispatch and a mutated early-exit displacement.
