# Node #115 MIME type parsing

This RE-002 packet links MIME media-type parsing and parameter normalization to released mime 0.3.18 source. The parser recognizes type/subtype, suffix and parameter delimiters; normalization lowercases the type and parameter names and handles charset values. Two complete catalogued node bodies match compiled references outside relocation fields. This static evidence does not establish exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-mime-type-parser/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
