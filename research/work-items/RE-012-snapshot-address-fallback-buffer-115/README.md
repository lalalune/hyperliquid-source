# RE-012: map node #115 address fallback buffer and NUL gate

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: qualify the fallback input preparation called from 0x5ca7e3d. Lengths at most 383 copy into the stack buffer and append NUL at the original length. The short scanner (length at most 14) explicitly inspects indices through the terminator. The shared first-NUL continuation calls 0x5c81c00 only if the observed offset equals the original length. Earlier NUL instead selects the record at 0x64c2fb8 and the internal tag-one error path, which writes output tag zero and a payload qword. Lengths above 383 skip this stack route and call 0x5c78d90 with the original pointer and length. This establishes the preparation and rejection paths without asserting the behavior of the resolver callees.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-address-fallback-buffer-115/collect.py --out work/node115-snapshot-address-fallback-buffer-fresh
python3 -B research/work-items/RE-012-snapshot-address-fallback-buffer-115/verify.py --out work/node115-snapshot-address-fallback-buffer-check-fresh.json
```
