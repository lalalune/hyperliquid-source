# Node #115 h2 Reason display descriptions

This RE-002 packet checks all 14 h2 reason descriptions and the unknown fallback used by `Display`. The full node body matches its compiled reference outside relocation fields, and linked relative offsets and lengths resolve to the released source's descriptive sentences. These are the Display descriptions, distinct from the Debug symbolic labels documented in #7692. This static evidence does not establish the exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF as data.

Run from repository root: `python3 -B research/work-items/RE-002-node115-h2-reason-display-descriptions/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
