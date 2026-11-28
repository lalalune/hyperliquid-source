# Node #115 rustc-demangle hexadecimal integer conversion

This RE-002 packet identifies the `HexNibbles::try_parse_uint` path. The released rustc-demangle source trims leading zeroes, rejects more than 16 remaining nibbles and accumulates a base-16 unsigned value. The node's catalogued body matches the compiled reference outside relocation fields; selected machine instructions verify the length and shift/or operations and the zero literal reference. The evidence supports this source linkage, not a production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The offline verifier checks the released crate checksum and reads the ELF as data.

Run from repository root: `python3 -B research/work-items/RE-002-node115-rust-demangle-hex-uint/verify.py /path/to/vendor-source`. The accompanying log is actual verifier output; manifest covers the packet.
