# RE-012: map node115 BIO callbacks and retry flag projection

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The paired callbacks first clear mask 0xf and obtain BIO data.
The read callback at 0x14e3100 calls the recv adapter and
uses the returned cursor as the count after a bounds check.
A pending return selects constant 0xd00000003. On a
nonzero error, the predicate controls whether mask 0x9
is set. It replaces the saved error at state +0x28 and
returns -1.

The write callback at 0x14e32e0 calls the send adapter.
Its selected result tags one and two store the error and
return -1, with tag two supplying the same fixed constant.
The predicate controls mask 0xa. This packet closes the
direction-specific bridge to BIO flags and saved errors,
separate from BIO construction and SSL read/write wrappers.

The retained 2 full FDEs cover 871 bytes and 235 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 6 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-tls-bio-callback-retry-115/collect.py --out work/tls-bio-callback-retry-fresh
python3 -B research/work-items/RE-012-tls-bio-callback-retry-115/verify.py --out work/tls-bio-callback-retry-check-fresh.json
```
