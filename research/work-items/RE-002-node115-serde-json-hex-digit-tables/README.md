# RE-002: serde_json hexadecimal digit tables in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The two complete 256-entry tables reproduce the signed i16 source representation and the nibble shift. Two distinct instructions route through GOT slots whose RELATIVE addends resolve to the table bases. Earlier JSON string writer and diagnostic work cover independent paths.

Place serde_json-1.0.140.crate from static.crates.io in the offline cache. The verifier
checks the archive digest and reads the captured ELF as data. Run from the
repository root with Python and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-serde-json-hex-digit-tables/verify.py /path/to/cache /path/to/binutils
```
