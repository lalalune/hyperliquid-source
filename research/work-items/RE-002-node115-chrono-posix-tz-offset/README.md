# Node #115 chrono POSIX timezone offset parsing

This RE-002 packet links local POSIX timezone offset and clock-component parsers to released chrono 0.4.38 source. The source parses signed hours with optional minute and second components, validates their ranges and computes seconds. Two complete catalogued node bodies match compiled references outside relocation fields; selected target instructions verify the hour/minute/second bounds, units and helper call. This static evidence does not establish exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-chrono-posix-tz-offset/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
