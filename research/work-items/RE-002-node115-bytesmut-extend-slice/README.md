# Node #115 BytesMut slice extension

This RE-002 packet links `BytesMut::extend_from_slice` to released bytes 1.11.1 source. The source reserves capacity, copies the supplied slice and advances the initialized length. The full catalogued #115 body matches its compiled reference outside relocation fields, and selected instructions corroborate the capacity comparison, destination arithmetic and length advancement. Static evidence does not prove the exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-bytesmut-extend-slice/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
