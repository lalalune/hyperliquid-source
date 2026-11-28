# Node #115 sysinfo NUL-separated process file parsing

This RE-002 packet links the Linux sysinfo process file parser to released sysinfo source. The source reads a file into a byte buffer and gathers nonempty NUL-separated UTF-8 entries. The full catalogued #115 body matches its compiled reference outside relocation fields; selected instructions corroborate the initial buffer capacities and NUL delimiter. Static evidence does not establish the exact production crate version or complete runtime behavior.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-sysinfo-nul-file-parser/verify.py /path/to/vendor-source`. The log is actual offline output; manifest covers the packet.
