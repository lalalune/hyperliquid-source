# RE-012: map node #115 snapshot optional literal field wrapper

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The dbOrder body passes several optional fields through 0x260d910. It tests the first descriptor byte before calling the shared key helper. The selected write branches test remaining room against 3 and 4 at distinct sites. The retained fallback reaches slot 0x64e0b08. This packet captures the actual wrapper and writer status boundaries.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-optional-literal-field-115/collect.py --out work/node115-snapshot-optional-literal-field-fresh
python3 -B research/work-items/RE-012-snapshot-optional-literal-field-115/verify.py --out work/node115-snapshot-optional-literal-field-check-fresh.json
```
