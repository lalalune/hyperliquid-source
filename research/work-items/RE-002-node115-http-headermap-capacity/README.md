# Node #115 HTTP HeaderMap initial capacity

This RE-002 packet links `HeaderMap::try_with_capacity` to released http 0.2.12 source. The source handles zero capacity, scales nonzero capacity, rounds to a checked power of two and rejects values above 32,768. Two complete catalogued #115 bodies match compiled references outside relocation fields; selected target instructions corroborate the zero case, arithmetic and size bound. This static evidence does not establish exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-http-headermap-capacity/verify.py /path/to/vendor-source`. The log is actual offline output; manifest covers the packet.
