# Node #115 sysinfo component file readers

This RE-002 packet links Linux sysinfo component text and numeric readers to released source. The text helper trims the line ending; the numeric helper reads up to 32 bytes, validates UTF-8, trims and parses a value. Both full catalogued node bodies match compiled references outside relocation fields, and a selected target instruction checks the 32-byte read argument. This is static linkage evidence, not proof of exact production crate version or complete runtime behavior.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF as data.

Run from repository root: `python3 -B research/work-items/RE-002-node115-sysinfo-component-file-readers/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
