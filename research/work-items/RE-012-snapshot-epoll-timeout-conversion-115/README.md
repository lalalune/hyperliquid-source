# RE-012: recover node #115 epoll timeout rounding and event publication

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The poller reserves nanoseconds equal to one billion as a sentinel for timeout -1. For ordinary values it adds 999999 nanoseconds, carrying one second at the threshold 999000001, then converts the normalized remainder to milliseconds using multiplier 0x431bde83 and shift 50. The 128-bit seconds-times-1000 product and the fractional sum saturate to INT_MAX on high-word overflow or excessive low word. A seconds value of all ones on the carry path is handled separately before addition.

Before epoll_wait the poller clears the previously published event count. A nonnegative result is published as a zero-extended count, while a negative result enters errno handling. Event indexing uses three dwords per entry and loads the token at byte offset four; zero tokens bypass the nonzero token dispatch. This documents timeout conversion and the immediate poll result contract.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-epoll-timeout-conversion-115/collect.py --out work/node115-snapshot-epoll-timeout-conversion-fresh
python3 -B research/work-items/RE-012-snapshot-epoll-timeout-conversion-115/verify.py --out work/node115-snapshot-epoll-timeout-conversion-check-fresh.json
```
