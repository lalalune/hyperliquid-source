# Node #115 object identifier arc iteration and display

This RE-002 packet examines object identifier arc iteration and dotted display against released const-oid 0.9.6 source. The source derives the two root arcs from the first octet and decodes subsequent arcs in base 128; display separates arcs with dots. Two complete catalogued target bodies are compared with compiled references outside relocation fields. Static evidence does not establish the exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Run `python3 -B research/work-items/RE-002-node115-const-oid-display/verify.py /path/to/vendor-source` from repository root. The log is actual offline output; the manifest covers the packet.
