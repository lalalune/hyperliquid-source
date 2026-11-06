# RE-009 · Partial-chunk finalization and saved-value fold

Target Linux x86-64 Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The final output path calls 0x160ab60 at 0x160bce0. This packet traces the partial-chunk input and its join with the saved-value stack. The no-partial-input seed using two saved values is a separate route.

If the saved-value count is zero, 0x160aca1 builds an output record directly from the chunk context. The record keeps the current counter and byte count. Its flags combine the context flags, bit 1 and bit 0 when context byte +0x69 is zero. The hardware selector moves from context +0x6b to result +0x6a.

With saved values and a nonzero OR of context bytes +0x68 and +0x69, the helper first stages a chunk-end compression with the same flag formula. The five table entries at 0x46aae8 select four destinations. The returned 32-byte value supplies the right half of a new parent input and the saved value at index count−1 supplies the left half. The helper loads the 32-byte parent seed from context +0x70 and stages a zero counter, length 64 and the context flags OR 4. If this consumed the last saved value, it publishes that parent without compressing it here.

If another saved value remains, the table at 0x46aafc selects the parent compression route. After each compression the next saved value becomes the left half and the compressed parent becomes the right half. The saved values are therefore projected from highest index to zero. The final parent record is left to the enclosing finalizer. These conclusions assume valid context fields, an in-range selector and ordinary returns from the compression helpers. The proof does not run the artifact or compute a digest from captured state.

Run `python3 research/work-items/RE-009-node115-root-digest-partial-fold/verify.py` from the repository root. The verifier checks the authenticated ELF, the extent, selected instructions and edge displacements, both dispatch tables and 64 synthetic stack walks.
