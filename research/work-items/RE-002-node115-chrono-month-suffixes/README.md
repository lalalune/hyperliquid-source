# RE-002: Chrono month suffix table in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

The month suffix lookup uses a linked table of twelve 16-byte string records. The verifier checks the RIP-relative base and index scale, resolves all eleven nonempty data pointers, and checks each length and full suffix against the pinned source. The empty May record has no pointer relocation and the November and December records share bytes.

Place chrono-0.4.38.crate in an offline cache. The published artifact is at https://static.crates.io/crates/chrono/chrono-0.4.38.crate. The verifier pins the archive digest. Run from the repository root with Python 3.9+ and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-chrono-month-suffixes/verify.py /path/to/cache /path/to/binutils
```

The verifier reads the crate and captured ELF as data. No captured executable is run.
