# RE-002: RocksDB status subcode text table in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The 16 pointer slots resolve to the complete source-defined status subcode texts in order. A linked formatter operand verifies the table base. Earlier status table work targeted node #94.

Place the public librocksdb-sys-0.11.0+8.1.1.crate archive in a source cache. Run
from the repository root with Python 3.9 or later and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-rocksdb-status-subcode-messages/verify.py /path/to/cache /path/to/binutils
```
