# Node #115 URL opaque host parsing

This RE-002 packet links URL opaque-host parsing to released url 2.5.4 source. The source handles bracketed IPv6, rejects forbidden host characters and percent-encodes controls in other opaque domains. The complete catalogued node body matches its compiled reference outside relocation fields; target instructions verify the bracket checks and direct IPv6-parser call. This is distinct from the separately documented IP parser and does not establish exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-url-opaque-host/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
