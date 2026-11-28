# RE-006: decimal scale in the selected perpetual TWAP finish status

The finish handoff in #4329 and #7072 selects this builder but leaves its internal projection open. In the selected branch of builder `0x5181da0`, the market index is checked against the descriptor's count before reading byte +0x1d of a 32-byte market record. The builder requires the byte d to be below 7. It selects binary64 table entry 6−d from `0x91b7c0`, whose seven values are 1 through 1,000,000 in powers of ten.

For the normal selected return, the qwords at local stack offsets +0x48 and +0x50 are converted through the unsigned binary64 two-lane sequence and divided by the same table entry. The respective results are stored at output +8 and +0x28. Output +0 is 1 when the first qword is nonzero and 0 otherwise. This binds the two scale consumers in this builder. The stack fields' upstream provenance, market-byte source meaning, other builder variants, FP environment and final event interpretation remain open.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are ELF VAs. The nearby perp_meta Location packet at `0x5182164` covers an error-site reference. It does not establish the normal scale-and-store path. No component gate changes.

Run `PYTHONPATH=tools python3 -B research/work-items/RE-006-node115-twap-perp-status-scale/verify.py` from the root. This reads the capture without executing it. Selected GNU disassembly and output are retained alongside the verifier.
