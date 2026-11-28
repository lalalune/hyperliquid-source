# Node #115 time-zone rule name and offset parsing

This RE-002 packet examines time-zone rule name and offset parsing against released chrono 0.4.38 source. Names use alphabetic or angle-bracketed syntax; offsets parse optional minute and second fields and check their bounds. The verifier compares complete catalogued target bodies with their compiled reference outside relocation fields. This static evidence does not establish the exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. From repository root run `python3 -B research/work-items/RE-002-node115-chrono-tz-rule-parse/verify.py /path/to/vendor-source`. The log is actual offline output; the manifest covers the packet.
