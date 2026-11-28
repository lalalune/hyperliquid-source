# Node #115 Hyper date cache refresh

This RE-002 packet links Hyper's cached HTTP date refresh to released Hyper 0.14.32 source. The cache updates only after its next-update time and then schedules the next update one second later. The complete catalogued node body matches its compiled reference outside relocation fields; selected instructions corroborate time comparison and one-second arithmetic. This static evidence does not establish exact production crate version or runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-hyper-date-cache/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
