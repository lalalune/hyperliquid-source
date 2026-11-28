# Node #115 UTF-16 trie iteration

This RE-002 packet examines UTF-16 trie iteration against released icu_collections-1.5.0 source. The reference traverses a UTF-16 trie and distinguishes intermediate, final and no-match results. The verifier compares complete catalogued target bodies with compiled references outside relocation fields. Static evidence does not establish the exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. From repository root run `python3 -B research/work-items/RE-002-node115-icu-char16-trie/verify.py /path/to/vendor-source`. The log is actual offline output; the manifest covers the packet.
