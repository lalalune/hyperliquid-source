# RE-012: map node #115 address result iterator and length gates

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: qualify the addrinfo result iterator reached through fallback slot 0x64ec950. It loads the current node from iterator+8 and publishes the next pointer from node+0x28 before inspecting the current address. It reads the address pointer from node+0x18 and a length dword from +0x10. Address family 2 requires length at least 16, and family 10 requires at least 28; each reads and byte-swaps the word at address+2. Other families take the helper path and repeat if the saved next pointer is nonnull. Exhaustion writes output tag two. This is static iterator and bounds evidence; it does not run or characterize a live resolver.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-address-result-iterator-115/collect.py --out work/node115-snapshot-address-result-iterator-fresh
python3 -B research/work-items/RE-012-snapshot-address-result-iterator-115/verify.py --out work/node115-snapshot-address-result-iterator-check-fresh.json
```
