# Node #115 Zstandard FSE normalized-count reader

This RE-002 packet links the FSE normalized-count header reader to released zstd 1.5.7 source. The source handles short headers, initializes symbol counts, reads the little-endian bitstream and extracts the table log. The complete default and BMI2 catalogued node bodies match their compiled references outside relocation fields. This is static source-linkage evidence, not proof of exact production library version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source archive checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-zstd-fse-ncount-reader/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
