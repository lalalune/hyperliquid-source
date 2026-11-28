# Node #115 rustc-demangle v0 basic type table

This RE-002 packet verifies all 26 lowercase v0 type tags against the released rustc-demangle `basic_type` source: 21 type strings and five unmapped tags. The complete catalogued target function matches its compiled reference outside relocation fields. The verifier follows the target's RIP-relative references to length and pointer tables, resolves the ELF relative relocations and checks every string and length. This is offline evidence of the mapping, not proof of the production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source crate checksum and reads the ELF as data.

Run from repository root: `python3 -B research/work-items/RE-002-node115-rust-demangle-basic-type-table/verify.py /path/to/vendor-source`. The log is actual offline output; the manifest covers the packet.
