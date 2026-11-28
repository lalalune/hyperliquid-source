# Node #115 h2 receive frame length configuration

This RE-002 packet links h2's receive codec constructor to the released source. Its framing configuration uses a big-endian three-byte length and a nine-byte adjustment; the maximum frame size is constrained to 16,384 through 16,777,215 bytes. Two catalogued node constructor bodies match compiled references outside relocation fields. Selected target instructions corroborate the length/adjustment and range constants. This is static evidence, not proof of exact production crate version or complete runtime behavior.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF as data; no network is used.

Run from repository root: `python3 -B research/work-items/RE-002-node115-h2-receive-frame-limits/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
