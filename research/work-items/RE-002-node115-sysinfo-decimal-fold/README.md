# Node #115 sysinfo decimal byte fold

This RE-002 packet examines sysinfo decimal byte fold against released sysinfo-0.29.11 source. The source folds already supplied decimal bytes into an unsigned value; this packet makes no claim that arbitrary inputs are validated. The verifier compares complete catalogued target bodies with compiled references outside relocation fields. This evidence does not establish the exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. From repository root run `python3 -B research/work-items/RE-002-node115-sysinfo-decimal-fold/verify.py /path/to/vendor-source`. The log is actual offline output; the manifest covers the packet.
