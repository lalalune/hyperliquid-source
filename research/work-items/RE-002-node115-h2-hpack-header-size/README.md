# Node #115 h2 HPACK header size and values

This RE-002 packet links h2 HPACK header size and value accessors to released h2 source. The source counts 32 bytes of entry overhead plus name and value lengths, with explicit pseudo-header sizes. The two complete node bodies match compiled references outside relocation fields; selected instructions verify the overhead and pseudo-header size constants. This is static linkage evidence, not a claim of exact production crate version or complete runtime behavior.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF as data.

Run from repository root: `python3 -B research/work-items/RE-002-node115-h2-hpack-header-size/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
