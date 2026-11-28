# Node #115 limited HTTP body read

This RE-002 packet links the http-body limited adapter to released http-body 0.4.6 source. It passes pending and end states through, subtracts each accepted data length from the remaining allowance and returns a length-limit error when a chunk exceeds it. The complete catalogued node body matches the compiled reference outside relocation fields; selected instructions corroborate the subtraction and reset. This is distinct from Hyper body polling and does not establish exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-http-body-limited-read/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
