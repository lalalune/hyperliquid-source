# RE-002: URL percent-encoding ASCII sets in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

Six source-defined AsciiSet masks match a total of 96 linked bytes. One selected code reference binds each bitmap to its role. The source derives the masks from the fixed ASCII control set and explicit additions. The userinfo mask is outside the matched cohort.

Place url-2.5.4.crate and percent-encoding-2.3.1.crate from static.crates.io in the offline cache. The verifier
checks the archive digests and reads the captured ELF as data. Run from the
repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-url-encoding-ascii-sets/verify.py /path/to/cache
```
