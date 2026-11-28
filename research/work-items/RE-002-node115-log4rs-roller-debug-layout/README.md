# RE-002: FixedWindowRoller debug layout in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The type and four field labels match the pinned log4rs source. The selected field addressing proves the three nonzero offsets and the linked four-field formatter destination. This concerns the formatter instance.

Place log4rs-1.3.0.crate from static.crates.io in the offline cache. The verifier
checks the archive digests and reads the captured ELF as data. Run from the
repository root with Python 3.9 or later and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-log4rs-roller-debug-layout/verify.py /path/to/cache /path/to/binutils
```
