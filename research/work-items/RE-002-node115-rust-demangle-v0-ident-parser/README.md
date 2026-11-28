# Node #115 rustc-demangle v0 identifier parsing

This RE-002 packet links the v0 identifier parser to released rustc-demangle source. The parser recognizes the optional `u` marker and `_` separator, reads a decimal length with checked arithmetic and bounds the resulting slice. The full catalogued node body matches its compiled reference outside relocation fields; selected target instructions verify marker constants, decimal operations and the corresponding bounds checks. The result does not establish the exact production crate version or full runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source crate checksum and treats the ELF as data.

Run from repository root: `python3 -B research/work-items/RE-002-node115-rust-demangle-v0-ident-parser/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
