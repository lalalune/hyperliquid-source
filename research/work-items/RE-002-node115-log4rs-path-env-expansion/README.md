# Node #115 log4rs appender path environment expansion

This RE-002 packet links log4rs appender path environment expansion to released log4rs 1.3.0 source. The source identifies `$ENV{...}` placeholders, validates the name and replaces a terminated placeholder when the variable is available. Two complete catalogued node bodies match compiled references outside relocation fields. The offline verifier does not read environment variables or establish exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-log4rs-path-env-expansion/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
