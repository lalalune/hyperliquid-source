# RE-012: map node #115 snapshot alternate descriptor intake

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate buffer dispatch invokes 0x221dc30 at 0x2299da2. The entry treats first qword 2 as the span descriptor case and uses endpoint differences plus the reciprocal of three after shifting by five. For valid 96-byte spans this yields the element count. The other branch uses the stored count at +0x40. The worker retains a stack copy of the descriptor, calls the count-prefix helper at 0x221dccd and checks the result's first word against 2. The normal continuation contains a separate 128-byte allocation and zero-length initialization. This packet bounds descriptor intake and output setup; the remaining per-record fields are open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-alternate-descriptor-entry-115/collect.py --out work/node115-snapshot-alternate-descriptor-entry-fresh
python3 -B research/work-items/RE-012-snapshot-alternate-descriptor-entry-115/verify.py --out work/node115-snapshot-alternate-descriptor-entry-check-fresh.json
```
