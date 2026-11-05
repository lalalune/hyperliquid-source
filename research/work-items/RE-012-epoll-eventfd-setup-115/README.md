# RE-012: map node115 epoll eventfd setup and failure cleanup

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The constructor at 0x5ceeae0 first calls epoll_create1 with
0x80000, then eventfd with initial value zero and flags 0x80800.
It registers the eventfd using epoll_ctl operation 1. The event
record has dword 0x80002001 and an eight-byte zero payload.
Next fcntl duplicates the epoll descriptor using command 0x406
and minimum 3. The syscall boundaries are bound to their actual
dynamic imports.

The error edges read errno before descriptor cleanup. Failure
of epoll creation owns no descriptor. Failure of eventfd creation
closes the original epoll descriptor. Registration failure and
duplication failure close eventfd followed by the original epoll
descriptor. The error result stores 0x8000000000000000 and the
packed errno word at +0/+8.

The event storage request multiplies the supplied capacity by
12 and checks multiplication overflow and the sign bit. A zero
size uses the sentinel pointer one. The normal output publishes
the original epoll descriptor at +0x18, duplicate at +0x60 and
eventfd at +0x64. The 128-byte allocation is stored at +0x38.
This is a static constructor result and cleanup contract.
Allocator behavior, event consumption and kernel execution remain
outside the selected scope.

The retained 1 full FDEs cover 576 bytes and 147 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 10 instruction/data windows, 2 RELATIVE addends, 6 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-epoll-eventfd-setup-115/collect.py --out work/epoll-eventfd-setup-fresh
python3 -B research/work-items/RE-012-epoll-eventfd-setup-115/verify.py --out work/epoll-eventfd-setup-check-fresh.json
```
