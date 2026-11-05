# RE-012: map node115 entropy device readiness and retry policy

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This packet follows the device fallback of the entropy-fill routine.
The probe calls syscall 0x13e with arguments 1, 0, 0 and caches its
availability decision at 0x64f06b0. A negative probe with errno 38
or 1 selects the device route. That route checks the shared fd
at 0x64f06b8, takes the mutex if it sees -1, and checks again.

Initialization opens /dev/random with flags 0x80000, then polls one
stack record containing fd, events 1 and revents 0 with timeout -1.
A negative poll retries on errno 4 or 11. A nonnegative return
closes the first fd and opens /dev/urandom with the same flags.
Each open retries on errno 4. A terminal poll error saves its
normalized error across close and mutex release. A successful second
open publishes the fd before unlock.

The read loop uses the cached descriptor, advances the cursor and
reduces the remaining size on positive reads, and retries -1 only
for errno 4. Zero or an overcount returns 0x80000002. Nonpositive
errno is normalized to 0x80000001 on the selected error paths. The
packet records the instructions and embedded device names without
opening the devices or invoking the captured routine.

The retained 1 full FDEs cover 748 bytes and 202 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 9 instruction/data windows, 0 RELATIVE addends, 8 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-entropy-device-fallback-115/collect.py --out work/entropy-device-fallback-fresh
python3 -B research/work-items/RE-012-entropy-device-fallback-115/verify.py --out work/entropy-device-fallback-check-fresh.json
```
