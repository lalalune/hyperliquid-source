# RE-009 — Node #115 quantity four-row sort seeds

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

For at least eight rows, the short sort at `0x43b4e60` prepares four ordered rows at the start of each half. The two instances begin at `0x43b4e98` and `0x43b4f55`. Each orders two adjacent pairs by unsigned key, selects the low and high output pointers by comparing pair extrema, then orders the two remaining pointers. The six comparisons operate on first qwords, while each selected row is written to scratch in full as 16 bytes plus the final qword. Equal keys retain the order of their original rows.

For the second instance, both input and scratch bases advance by 24 times floor(n/2). The helper starts its extension step at four rows. The paired-end merge in #7593 consumes the ordered halves after this preparation. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-four-row-seeds/verify.py`.
