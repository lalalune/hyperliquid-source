# RE-002: Const-hex lookup data in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Three selected decoded RIP-relative references lead to the same 256-byte lookup table. Its full contents match the table derived from the pinned Rust source ranges. The comparison also checks three AVX2 broadcasts against the observed 16-bit constants. Previous operand research retains limited previews of those data locations.

Place const-hex-1.14.0.crate in an offline cache. The published artifact is at https://static.crates.io/crates/const-hex/const-hex-1.14.0.crate. The verifier pins the archive digest. Run from the repository root with Python 3.9+ and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-const-hex-lut/verify.py /path/to/cache /path/to/binutils
```

The verifier reads the crate and captured ELF as data. No captured executable is run.
