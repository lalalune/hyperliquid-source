# Node #115 HTTP-date conversion and formatting

This RE-002 packet links HTTP-date conversion and display to released httpdate 1.0.3 source. The source derives calendar fields from Unix time and formats a 29-byte weekday, date, time and GMT value. Both complete catalogued node bodies match compiled references outside relocation fields. This is distinct from Hyper's one-second date-cache scheduling; static evidence does not establish exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-httpdate-conversion-display/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
