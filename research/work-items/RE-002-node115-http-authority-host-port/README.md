# Node #115 HTTP authority host and port accessors

This RE-002 packet examines http authority host and port accessors against released http-0.2.12 source. The released HTTP source selects the authority host after userinfo, preserves bracketed IPv6 literals, and parses a port after the final colon. The verifier compares complete catalogued target bodies with their compiled reference outside relocation fields. This does not establish the exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. From the repository root run `python3 -B research/work-items/RE-002-node115-http-authority-host-port/verify.py /path/to/vendor-source`. The log is actual offline output; the manifest covers the packet.
