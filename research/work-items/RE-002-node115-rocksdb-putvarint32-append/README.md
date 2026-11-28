# RE-002: RocksDB PutVarint32 append adapter in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the catalogued PutVarint32 string append adapter outside recorded relocation fields and verify its encoder and string append references against pinned public RocksDB source. The encoder itself was previously covered by #2985.

Place librocksdb-sys-0.11.0+8.1.1.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-rocksdb-putvarint32-append/verify.py /path/to/cache
```
