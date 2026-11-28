# Node #115 promotable buffer conversions

This RE-002 packet examines the odd and even pointer variants used to convert promotable `Bytes` into a vector or mutable buffer against released bytes 1.11.1 source. The even variants clear the kind mask; the odd variants pass the shared pointer through. Four complete catalogued target bodies are compared with compiled references outside relocation fields. This static evidence does not establish the production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. From repository root run `python3 -B research/work-items/RE-002-node115-bytes-promotable-conversion/verify.py /path/to/vendor-source`. The log is actual offline output; the manifest covers the packet.
