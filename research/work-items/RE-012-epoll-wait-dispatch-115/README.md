# RE-012: map node115 epoll timeout and event result dispatch

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This follow-up starts from the already constructed epoll owner.
The timeout path uses -1 when the subsecond word equals 1000000000.
The finite branch adds 999999 to the subsecond word or carries into
the seconds path, uses reciprocal multiplication and shift for the
millisecond quotient, and saturates the resulting timeout at
0x7fffffff, including a nonzero high product/sum word.

Before epoll_wait it clears the prior length at owner +0x10.
The call uses fd at +0x18, storage at +8, capacity at +0 and the
computed timeout. A nonnegative return is published as the new
length. Zero skips iteration. The loop indexes 12-byte records
and reads the qword payload at record +4. Payload zero skips the
record, payload one sets owner +0x1c, and other payloads enter
the mask projection and atomic update at payload object +0x10
before calling 0x5cfd1d0. This scope retains the mask instructions
without assigning runtime types to the payload object.

Negative wait results read errno and construct (errno << 32) | 2.
The errno-4 branch calls 0x5cee460 and returns if it comes back;
there is no local epoll_wait retry on that edge. Other errors
enter the separate diagnostic path.

The retained 1 full FDEs cover 729 bytes and 189 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 7 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-epoll-wait-dispatch-115/collect.py --out work/epoll-wait-dispatch-fresh
python3 -B research/work-items/RE-012-epoll-wait-dispatch-115/verify.py --out work/epoll-wait-dispatch-check-fresh.json
```
