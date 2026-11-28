# Node #115 bytes generic buffer copy

This RE-002 packet links the generic `Buf::copy_to_bytes` operation to released bytes 1.11.1 source. The source checks the requested length against the remaining bytes, copies a limited view into an owned buffer and freezes the result. Three complete catalogued #115 instantiations match compiled references outside relocation fields. This is static source-linkage evidence, not proof of exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-bytes-buffer-copy/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
