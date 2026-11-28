# Node #115 bytes chained buffer behavior

This RE-002 packet links chained buffer advance and vectored chunk access to released bytes 1.11.1 source. The source consumes the first buffer before advancing into the second and combines vectored chunks from both. Four complete catalogued #115 bodies match separately compiled references outside relocation fields. These matches support source linkage; they do not prove exact production crate version or full runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-bytes-chain-buffer/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
