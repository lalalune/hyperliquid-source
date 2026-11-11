# RE-012: recover node #115 Unix socket pair descriptor ownership

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This helper creates an AF_UNIX socket pair via GLOB_DAT slot 0x64eb078. It preserves the supplied type bits while ORing in 0x80800, sets protocol zero, and initializes the two descriptor outputs to -1 before the call.

A negative syscall result stores output tag one and (errno << 32)|2 at +8. A nonnegative result still checks each returned descriptor against -1 before publishing tag zero and the two descriptors at +4 and +8. The second invalid-descriptor diagnostic is paired with a landing pad that closes the first descriptor and resumes unwinding. This recovers local descriptor-pair creation, its result layout, and partial-acquisition ownership.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-socketpair-ownership-115/collect.py --out work/node115-snapshot-socketpair-ownership-fresh
python3 -B research/work-items/RE-012-snapshot-socketpair-ownership-115/verify.py --out work/node115-snapshot-socketpair-ownership-check-fresh.json
```
