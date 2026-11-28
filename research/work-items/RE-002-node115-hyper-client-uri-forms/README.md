# Node #115 Hyper client URI form handling

This RE-002 packet links Hyper client URI origin form, pool-domain construction and scheme-setting helpers to released Hyper 0.14.32 source. The source retains the path/query for origin form, constructs a domain URI from scheme and authority and supplies `/` when setting a scheme. Three complete catalogued #115 bodies match compiled references outside relocation fields. This is static source-linkage evidence, distinct from h2 pseudo-header construction; it does not establish exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the crates.io source archive checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-hyper-client-uri-forms/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
