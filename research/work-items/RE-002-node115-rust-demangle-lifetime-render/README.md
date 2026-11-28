# Node #115 rustc-demangle lifetime rendering

This RE-002 packet links the v0 lifetime renderer to released rustc-demangle source. Its output handles the zero index, uses a checked bound-depth subtraction, emits alphabetic names for the first 26 values and uses an underscore and decimal beyond that. The full #115 body matches the compiled reference outside relocation fields; literal references and selected instructions verify the stated threshold and arithmetic. This evidence does not establish the production crate version or full runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF as data.

Run from repository root: `python3 -B research/work-items/RE-002-node115-rust-demangle-lifetime-render/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
