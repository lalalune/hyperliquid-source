# RE-009 — Node #115 quantity ordering of deferred runs

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The quantity ordering core at `0x3e73880` stores each run length in the high bits of a word. Its low bit records whether the run is already ordered. The natural-run output at `0x3e73b60` sets that bit, whereas `0x3e73a2c` forms a deferred run with the bit clear. The dispatch advances its row index by the descriptor shifted right once. When two deferred runs combine and their combined length fits scratch, the metadata can coalesce them by adding their lengths and keeping the low bit clear.

The publication at `0x3e73e86` stores that word alongside a separate one-byte position rank. On exhaustion the state checks the low bit before returning. A clear bit triggers the partition sorter through slot `0x64ea138`, passing the input base, total count, scratch capacity, twice the highest set-bit index of the total count as the budget, a null prior bound and the saved caller context.

This packet links run tagging to final dispatch. Threshold setup (#7589) and the scan comparisons (#7551) are independently documented. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-deferred-ordering/verify.py`.
