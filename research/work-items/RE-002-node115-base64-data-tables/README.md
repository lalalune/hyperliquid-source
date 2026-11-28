# RE-002: Base64 alphabet and inverse tables in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Two read-only data ranges each contain the full standard 64-byte alphabet followed by its 256-byte inverse table. Derivation from authenticated source reproduces both pairs. The verifier rejects the URL-safe pair at both placements. This does not attribute consumers or identify a unique crate version.

Place base64-0.21.7.crate in an offline cache. The published artifact is at https://static.crates.io/crates/base64/base64-0.21.7.crate. The verifier pins the archive digest. Run from the repository root with Python 3.9+ and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-base64-data-tables/verify.py /path/to/cache /path/to/binutils
```

The verifier reads the crate and captured ELF as data. No captured executable is run.
