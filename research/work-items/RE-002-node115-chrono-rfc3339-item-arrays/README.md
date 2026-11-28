# RE-002: Chrono date and time item arrays in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compiling the published declarations for Linux x86-64 reproduces the 168-byte date and 216-byte time objects. All four source literal-pointer relocations resolve to matching data in the linked target. Earlier Chrono parsing evidence (#3122) identifies the array addresses and previews their start.

Place chrono-0.4.38.crate from static.crates.io in the offline cache. The verifier
checks the archive digest and reads the captured ELF as data. Run from the
repository root with Python and GNU readelf, objcopy, objdump and rustup Rust 1.95.0 with x86_64-unknown-linux-gnu core.

```sh
python3 -B research/work-items/RE-002-node115-chrono-rfc3339-item-arrays/verify.py /path/to/cache /path/to/binutils
```
