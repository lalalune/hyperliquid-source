# Node #115 h2 request pseudo-header construction

This RE-002 packet links the h2 request pseudo-header builder and scheme helper to released h2 0.3.26 source. The source handles default `/` paths with OPTIONS and CONNECT exceptions, filters empty paths and propagates URI scheme and authority. Both complete catalogued node bodies match compiled references outside relocation fields; the target builder's `/` literal and direct scheme-helper call are verified. The evidence is static and does not establish exact production crate version or complete runtime behavior.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF as data. No network connection is made.

Run from repository root: `python3 -B research/work-items/RE-002-node115-h2-request-pseudo-fields/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
