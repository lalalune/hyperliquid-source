# RE-012: map node115 epoll interest projection and registration rollback

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The registration wrapper acquires the state-byte lock and calls
the bound registration allocator. A tag-one allocator result
releases the lock and exits. The other branch maps interest
bits before calling epoll_ctl operation one. The selected event
word starts at 0x80000000. For normalized interest byte I,
bit 0 selects base 0x80002001; (I & 2) times two supplies
the write mask, and (I >> 4) times two supplies the extra
mask. Absent input bits 0, 1 and 4 normalize to one. Otherwise
bit 5 can force normalized bit 0. The qword payload is the
allocated object address plus 0x80.

A negative epoll_ctl result packs errno and reacquires the state
lock. The rollback reads links at object +0x80/+0x88, repairs
neighbor or owner endpoint links on the matching branches,
clears the detached link pair and drops a reference. It releases
the lock and drops the temporary reference before returning
the error. This packet scopes initial registration and rollback,
separate from event wait and signal attachment.

The retained 1 full FDEs cover 648 bytes and 188 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-socket-readiness-registration-115/collect.py --out work/socket-readiness-registration-fresh
python3 -B research/work-items/RE-012-socket-readiness-registration-115/verify.py --out work/socket-readiness-registration-check-fresh.json
```
