# RE-012: resolve node #115 notification table publication race

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: bind the null-table continuation used by the TCP unlock notification. The existing RE-001 reports identify the constructor call but leave publication and ownership of competing allocations open.

0x5bb6400 constructs a candidate by passing (3, 0) to 0x5bb6460, then executes locked CMPXCHG through the pointer in slot 0x64ec148 with expected zero. Success returns the candidate unchanged. Failure saves the observed pointer returned by CMPXCHG, then, if candidate+8 is nonzero, calls the release slot 0x64df4a0 with candidate[0], candidate[8] shifted left six, and 6. It then releases the candidate descriptor using the same slot with size 0x20 and third argument zero, and returns the saved observed pointer. Thus both paths return the published pointer under the observed publication premise, but only the losing path releases its private allocation. Constructor internals and replacement/removal of a published table are separate.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-lock-table-publication-115/collect.py --out work/node115-snapshot-lock-table-publication-fresh
python3 -B research/work-items/RE-012-snapshot-lock-table-publication-115/verify.py --out work/node115-snapshot-lock-table-publication-check-fresh.json
```
