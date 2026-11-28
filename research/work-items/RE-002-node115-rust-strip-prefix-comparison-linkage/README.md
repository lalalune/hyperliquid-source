# RE-002: Path strip_prefix comparison linkage in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

Verify the complete catalogued strip-prefix implementation outside source relocations. Bind the direct Component equality call and the separate linked path-remainder address. The earlier Component::eq proof covered the callee body.

Place the pinned rust-src-1.95.0.tar.xz in the local source cache. Run from the repository root
with Python 3.9 or later and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-rust-strip-prefix-comparison-linkage/verify.py /path/to/cache /path/to/binutils
```
