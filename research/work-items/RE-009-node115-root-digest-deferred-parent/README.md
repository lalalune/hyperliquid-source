# RE-009 · Deferred final digest parent for two saved values

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The finalizer calls 0x160ab60 at 0x160bce0. The preparation helper reads the saved-value count at context +0x90. On the selected path, the count is two and both partial chunk bytes at +0x68 and +0x69 are zero. The helper takes the no-partial-input branch, forms n−2 and n−1 indexes, and reads the two 32-byte saved values at context +0x94 and +0xb4 in that order.

It stages the values as a 64-byte parent input, sets the counter to zero, sets input length to 64 and uses the context flag byte OR 4. With n=2 the remaining-parent test branches directly to the output-record stores at 0x160b067. Thus the preparation stage leaves this parent uncompressed for the enclosing finalizer to handle. The already studied outer finalizer adds bit 3 to the record's flags. This selected case leaves the larger stack fold, partial input and digest bytes unresolved.

Run python3 research/work-items/RE-009-node115-root-digest-deferred-parent/verify.py from the repository root. It checks the pinned artifact, preparation FDE, five branch or call edges, fourteen instructions and a mutated deferred-path edge.
