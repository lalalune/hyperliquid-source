# Node #115 bytes slice range handling

This RE-002 packet links `Bytes::slice` to released bytes 1.11.1 source. The source validates begin/end bounds, treats an empty range specially and constructs a shared view for nonempty slices. Two catalogued #115 bodies match compiled references outside relocation fields; selected instructions verify range comparisons and resulting pointer/length arithmetic. This is static evidence, not proof of the exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-bytes-slice-range/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
