# RE-012: map node115 file remaining-length query

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The wrapper passes the borrowed fd and flags 0x1000 to the
metadata helper. Tag three selects a zeroed fstat64 buffer,
tag two bypasses the seek and disposes of the error payload,
and the other metadata result supplies the file size.

The selected size is paired with lseek64(fd,0,1). On success
the output flag is one and the returned length is unsigned
saturating subtraction of current offset from size. A seek
result of -1 or failed fstat64 packs and drops the errno payload
and returns the absence flag. The statx capability probe is
covered separately. This scope follows its consumer and the
offset arithmetic.

The retained 1 full FDEs cover 299 bytes and 73 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-file-metadata-seek-fallback-115/collect.py --out work/file-metadata-seek-fallback-fresh
python3 -B research/work-items/RE-012-file-metadata-seek-fallback-115/verify.py --out work/file-metadata-seek-fallback-check-fresh.json
```
