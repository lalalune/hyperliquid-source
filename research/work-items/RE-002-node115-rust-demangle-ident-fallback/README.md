# Node #115 rustc-demangle Ident fallback linkage

This RE-002 offline packet identifies the fallback formatting path for a v0 identifier when the small Punycode decoder cannot emit decoded characters. The released rustc-demangle 0.1.27 source describes the `punycode{` prefix, conditional `-` separator and `}` suffix; the catalogued #115 native body links to the same literal bytes and lengths. This establishes source linkage and selected formatting constants, not full behavioral equivalence or an exact production crate version.

Base: `2da45cb0a761cff6b478e40421699857d87a94df`. Target `artifacts/node/115/hl-node`: SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source archive `rustc-demangle-0.1.27.crate` is checked against its crates.io checksum. The verifier reads the node ELF as data; no node binary or network service is run. It compares all non-relocation bytes of the full catalogued body and checks literal addresses, bytes and explicit output lengths.

Run from the repository root: `python3 -B research/work-items/RE-002-node115-rust-demangle-ident-fallback/verify.py /path/to/vendor-source`. `offline-log.txt` is output from this command; `MANIFEST.sha256` covers the packet.
