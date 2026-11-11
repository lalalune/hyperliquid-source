# RE-012: map node115 mutex contended acquisition and futex wait

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The std census attributes 0x5c843b0 to the contended mutex
acquisition routine. This packet resolves its state transitions and
binds one concrete caller. At 0x5c9d13b the caller attempts 0 to 1 on
the static word 0x6500080. Failure passes that same address through
the RELATIVE call slot 0x64e06a8. Both routes join at 0x5c9d145.

The contended body spins only while the word equals 1. The counter
starts at -99 and permits up to 100 pause/load iterations. Seeing 0
allows one compare-exchange from 0 to 1. A failed attempt uses the
observed word. If the word is not already 2, an exchange sets it to
2 and a prior zero returns with the contended state retained.

Before waiting, the body reloads the state and requires 2. The
imported syscall uses number 202, address of the state word,
operation 0x89, expected value 2, null timeout, null second address
and mask 0xffffffff. The timeout selector stays zero along this
entry. A negative syscall result reads errno. Value 4 returns to
the pre-wait state check. Other outcomes reload the lock and may
spin again before retrying acquisition. No live lock or syscall
is used in qualification. Kernel scheduling and fairness are
outside the static contract.

The retained 2 full FDEs cover 330 bytes and 103 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 10 instruction/data windows, 1 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-mutex-contended-115/collect.py --out work/mutex-contended-fresh
python3 -B research/work-items/RE-012-mutex-contended-115/verify.py --out work/mutex-contended-check-fresh.json
```
