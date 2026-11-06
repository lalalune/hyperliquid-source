# RE-012: recover node #115 thread guard teardown and registry root contraction

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The bootstrap's teardown path enters this routine with the pointer returned by alternate-stack setup. For a nonzero pointer it recomputes the usable size as max(8192, getauxval(0x33)), calls sigaltstack with a zero base and SS_DISABLE, then passes the pointer minus the guard length and the combined length to munmap. A zero pointer skips both external operations and still proceeds to the registry.

Registry deletion takes the same outer lock and errno-pointer owner slot as the registration path. In the recovered root-contraction branch a successful removal decrements the global count; when the contraction flag is one and the root and depth are nonzero, the first child at root +0x220 becomes the new root. The stored depth is decremented and the promoted child's parent qword is cleared before the old 0x280-byte root is freed. The removed payload's name storage is released separately if both pointer and length are nonzero. This packet covers the teardown and root contraction, leaving individual redistribution cases as boundaries.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-thread-guard-teardown-115/collect.py --out work/node115-snapshot-thread-guard-teardown-fresh
python3 -B research/work-items/RE-012-snapshot-thread-guard-teardown-115/verify.py --out work/node115-snapshot-thread-guard-teardown-check-fresh.json
```
