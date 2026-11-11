# RE-012: map node115 pidfd ancillary message send and receive

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The sender calls syscall 0x1b2 with getpid and flags zero.
It always constructs a single iovec and sends with flags zero.
A nonnegative syscall result adds a control buffer of 24 bytes,
with cmsg length 20, level 1, type 1 and the descriptor dword.
A negative result leaves the control pointer and length zero.
The sendmsg loop retries -1 only for errno 4.

The complementary receive branch supplies 24 bytes of control
storage and flags 0x40000000. It retries -1 for errno 4, retaining
the same message pointer and flags. The candidate fd starts at -1.
On the non-error route the control pointer must be nonnull and
its reported span at least 16. It then checks level 1, type 1,
and cmsg length 20 before loading the dword at +16. Only a
nonnegative dword replaces the candidate. The -1 sentinel is
also used after a terminal receive error. This packet follows
descriptor transfer and admission up to the next process
handshake. Child wait, polling and ioctl are separate paths.

The retained 2 full FDEs cover 10282 bytes and 2102 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 8 instruction/data windows, 0 RELATIVE addends, 5 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-pidfd-control-handoff-115/collect.py --out work/pidfd-control-handoff-fresh
python3 -B research/work-items/RE-012-pidfd-control-handoff-115/verify.py --out work/pidfd-control-handoff-check-fresh.json
```
