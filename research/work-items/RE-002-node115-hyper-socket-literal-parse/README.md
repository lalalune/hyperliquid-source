# Node #115 Hyper literal socket address parsing

This RE-002 packet links Hyper's literal socket address parser to released Hyper 0.14.32 source. The source attempts IPv4 and IPv6 parsing, attaches the supplied port and returns no result for a nonliteral host. The complete catalogued node body matches its compiled reference outside relocation fields. This is distinct from the documented private-fork DNS selection and is static source-linkage evidence, not proof of exact production crate version or active networking behavior.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the released source checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-hyper-socket-literal-parse/verify.py /path/to/vendor-source`. Log is actual offline output; manifest covers the packet.
