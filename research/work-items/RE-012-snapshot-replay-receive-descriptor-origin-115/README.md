# RE-017: trace node #115 replay receive descriptor to first queue probe

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

PR #3813 records the first receive probe and #3816 records its segment and slot algorithm. PRs #3875 and #3877 track the separate expected-record word. This packet connects the receive descriptor to the callback on the selected original-input arm.

Adapter 0x2a92960 copies callback +0x6c0..+0x6df to its stack +0x30 and passes that address in RDX. The worker saves RDX at stack +0x160 and reloads it into RSI for receive helper 0x5ab6df0. The helper saves RSI at stack +0x28. At 0x5ab6eff..0x5ab6f0b it forwards that saved pointer to stack +0x10 if BL is zero. A nonzero BL replaces the pointer with R14 and checks for mode three; this packet does not extend the original-input claim to that arm.

At 0x5ab6f60 the selected pointer is dereferenced once. For the original-input arm, let Q be the first qword of the projected callback record. The first probe receives Q+0x1a0 as RSI and Q+0x80 as RDX. Composing that projection with #3816 gives index I = [Q+0x1b0] and initial segment pointer [Q+0x1a0]. The probe seeks a segment whose +0x200 equals I & ~31 by following +0x208 links. At the selected ready slot it reads 16 bytes at segment + 16*(I & 31). A missing segment link returns tag two. Concrete segment and slot values require the initialized object. The packet does not infer I from checkpoint height.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-replay-receive-descriptor-origin-115/collect.py --out work/node115-snapshot-replay-receive-descriptor-origin-fresh
python3 -B research/work-items/RE-012-snapshot-replay-receive-descriptor-origin-115/verify.py --out work/node115-snapshot-replay-receive-descriptor-origin-check-fresh.json
```
