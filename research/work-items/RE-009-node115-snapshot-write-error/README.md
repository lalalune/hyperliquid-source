# RE-009 · Snapshot write error context

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The linked-state save path already identifies the write boundary. On a nonzero write result, the selected caller at 0x1502575 passes its two stack records and that returned word to 0x15026e0.

The wrapper builds three address/formatter pairs from its two pointer arguments and the address of a local copy of the third argument. It passes those pairs with the encoded descriptor containing `write_bytes_to_file` to 0x150d950. It preserves that call's returned word, then calls 0x150c590 on the local copy of the incoming third argument before returning. The separate landing sequence also calls 0x150c590 before its unwind continuation. The cleanup helper masks the incoming word to its low two bits and only enters the selected indirect destructor path for tag 1. This pins the contextual error inputs and local cleanup order. The rendered error string and downstream reporting remain open.

Run `python3 research/work-items/RE-009-node115-snapshot-write-error/verify.py` from the repository root to check the authenticated windows and descriptor.
