# Node #115 Zstandard FSE table-log selection

This RE-002 packet links finite-state entropy table-log selection to released zstd 1.5.7 source. The source considers input size, maximum symbol value, an optional default and minimum and maximum table-log bounds. The internal selector and public wrapper match their complete catalogued node references outside relocation fields. This static evidence does not establish exact production library version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source archive checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-zstd-fse-tablelog/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
