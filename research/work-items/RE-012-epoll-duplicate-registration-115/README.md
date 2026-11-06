# RE-012: map node115 signal descriptor duplicate ownership on epoll attach

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This packet follows ownership in the signal attachment
consumer. It reads the shared fd at 0x64fee24 and duplicates
it with fcntl command 0x406 and minimum three. The duplicate
is registered with epoll_ctl operation one, event word
0x80002001 and payload one. The global socketpair producer
and wake writer are covered in #2952 and #2974.

Success copies the supplied owner record, stores the fresh
allocation at +0x20 and the duplicate at +0x28. Duplication
failure stores the high-bit sentinel and packed errno and
releases the supplied storage and fd. Registration failure
stores the error before closing the duplicate, then follows
the same release path. This is the attachment cleanup and
result layout, separate from the global producer.

The retained 1 full FDEs cover 388 bytes and 97 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 4 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-epoll-duplicate-registration-115/collect.py --out work/epoll-duplicate-registration-fresh
python3 -B research/work-items/RE-012-epoll-duplicate-registration-115/verify.py --out work/epoll-duplicate-registration-check-fresh.json
```
