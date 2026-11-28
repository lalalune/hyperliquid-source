# Node #115 Unicode combining class lookup

This RE-002 packet examines Unicode combining class lookup against released icu_normalizer-1.5.0 source. The reference obtains canonical combining classes from Unicode data and caches class values for normalization. The verifier compares complete catalogued target bodies with compiled references outside relocation fields. Static evidence does not establish the exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. From repository root run `python3 -B research/work-items/RE-002-node115-icu-combining-class/verify.py /path/to/vendor-source`. The log is actual offline output; the manifest covers the packet.
