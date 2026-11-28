# Node #115 two-needle byte search

This RE-002 packet examines the memchr two-byte searcher against released memchr 2.8.3 source. The released implementation selects scalar, SSE2 or AVX2 paths depending on slice length. Two complete catalogued search bodies match compiled references outside relocation fields. Earlier research bound an AVX dispatcher destination and characterized separate SSE reverse and count paths; this packet examines two-needle bodies. Static evidence does not establish the exact production crate version, live CPU dispatch or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Run `python3 -B research/work-items/RE-002-node115-memchr-two-needle/verify.py /path/to/vendor-source` from repository root. The log is actual offline output; the manifest covers the packet.
