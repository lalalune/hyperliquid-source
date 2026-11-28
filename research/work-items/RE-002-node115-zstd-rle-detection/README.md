# Node #115 Zstandard run-length detection

This RE-002 packet links Zstandard's uniform-byte block detector to released zstd 1.5.7 source. The source compares a short prefix and then scans four machine words per iteration against a repeated-byte word. The complete catalogued node body matches the compiled reference outside relocation fields; selected target instructions corroborate the single-byte case, repeated-byte constant and 32-byte iteration. This static evidence does not establish exact production library version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source archive checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-zstd-rle-detection/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
