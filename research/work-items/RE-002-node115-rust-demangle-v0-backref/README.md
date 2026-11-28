# Node #115 rustc-demangle v0 back-reference handling

This RE-002 packet identifies v0 back-reference parsing and its printer wrapper. Released rustc-demangle source constructs a parser from an earlier base-62 offset, applies the depth limit and restores the original parser after printing. The matching #115 parser body calls the catalogued integer decoder and contains the backward comparison and 500 depth bound; both parser and printer bodies are checked outside relocation fields. This shows source linkage and selected instructions, not complete runtime equivalence or a production crate version.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released crate checksum and reads the ELF only as data.

Run from repository root: `python3 -B research/work-items/RE-002-node115-rust-demangle-v0-backref/verify.py /path/to/vendor-source`. The log is actual offline output; manifest covers the packet.
