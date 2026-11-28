# Node #115 Hyper body sender readiness and errors

This RE-002 packet links Hyper body sender readiness and error delivery to released Hyper 0.14.32 source. The sender checks receiver demand and channel readiness; error delivery uses a cloned sender to attempt an error send. Two complete catalogued node bodies match their compiled references outside relocation fields. This static evidence does not establish exact production crate version, active network behavior or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-hyper-body-sender/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
