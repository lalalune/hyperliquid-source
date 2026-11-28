# Node #115 chrono POSIX timezone transition rules

This RE-002 packet links local timezone transition-day parsing to released chrono 0.4.38 source. The source supports month-weekday and two Julian-day forms, with a default transition time of 02:00 when no explicit time is supplied. The complete catalogued node body matches the compiled reference outside relocation fields; selected instructions corroborate form markers, a Julian bound and the 7,200-second default. This static evidence does not establish exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-chrono-posix-tz-transition/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
