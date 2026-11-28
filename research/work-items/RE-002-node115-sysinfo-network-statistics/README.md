# Node #115 sysinfo Linux network statistics

This RE-002 packet links Linux network interface enumeration and refresh to released sysinfo source. The source reads six receive/transmit byte, packet and error counters from sysfs and maintains old and new samples. Two complete catalogued node bodies match their compiled references outside relocation fields; eight RIP-relative references link the sysfs path, statistics directory and six counter names. This is static linkage evidence, not a claim of exact production crate version or runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF as data; it does not query a live node.

Run from repository root: `python3 -B research/work-items/RE-002-node115-sysinfo-network-statistics/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
