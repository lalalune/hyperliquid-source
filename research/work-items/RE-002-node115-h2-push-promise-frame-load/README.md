# Node #115 h2 PUSH_PROMISE frame loading

This RE-002 packet links the h2 PUSH_PROMISE frame loader to released h2 source. The source handles the padding flag, reads a four-byte promised stream identifier and retains the remaining header block. The full catalogued node body matches the compiled reference outside relocation fields. Selected instructions corroborate the padding flag, minimum payload size, identifier width and byte order. This static analysis does not establish exact production crate version or complete runtime behavior.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF as data. No network is used.

Run from repository root: `python3 -B research/work-items/RE-002-node115-h2-push-promise-frame-load/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
