# Node #115 Zstandard frame header encoding

This RE-002 packet links frame header writing to released zstd 1.5.7 source. The source emits the frame magic, descriptor flags, dictionary ID and variable-width content size. The complete catalogued node body matches the compiled reference outside relocation fields; selected instructions corroborate the magic, size threshold and two-byte size adjustment. This static evidence does not establish the exact production library version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source archive checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-zstd-frame-header-encode/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
