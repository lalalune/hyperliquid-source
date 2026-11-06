# RE-012: recover node #115 alternate stack teardown and mapping release

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The teardown entry tests its pointer argument before issuing any stack-related calls. For a nonnull pointer it recomputes max(getauxval(0x33), 0x2000) and loads the global length from 0x6500048. It passes a stack descriptor with null pointer, flags two and the recomputed usable size to sigaltstack.

It then calls munmap with the original pointer minus the global length and the usable size plus that length. The two calls are consecutive in control flow without a return-value test. The null-pointer path bypasses both calls. Both paths join at 0x5ca397b, which obtains the errno pointer before a separate locked update of the word at 0x6500028. The packet focuses on the release path and its handoff to the remaining worker.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-alternate-stack-release-115/collect.py --out work/node115-snapshot-alternate-stack-release-fresh
python3 -B research/work-items/RE-012-snapshot-alternate-stack-release-115/verify.py --out work/node115-snapshot-alternate-stack-release-check-fresh.json
```
