# Node #115 Hyper H2 keepalive timeout check

This RE-002 packet links Hyper's H2 keepalive timeout status check to released Hyper 0.14.32 source. The source locks shared state, returns the keepalive timeout error when its flag is set and otherwise succeeds. The complete catalogued node body matches its compiled reference outside relocation fields. This static evidence is distinct from the h2 ping payload mapping and does not establish exact production crate version, active network behavior or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-hyper-h2-keepalive-timeout/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
