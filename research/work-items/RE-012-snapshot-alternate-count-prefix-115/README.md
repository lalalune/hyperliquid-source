# RE-012: map node #115 snapshot alternate count prefix

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate snapshot worker calls 0x25e7940 at 0x2299b85 and checks the first result word for tag 2. This packet follows the callee's count-dependent prefix. The entry compares the 32-bit argument with 16 and 65,536. The observed header branches contain byte values 0xdc and 0xdd. Each width-specific output path has its own capacity check and status test after 0x231dc90. The retained exports separate the header writes from the result publication, leaving the enclosing value's schema open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-alternate-count-prefix-115/collect.py --out work/node115-snapshot-alternate-count-prefix-fresh
python3 -B research/work-items/RE-012-snapshot-alternate-count-prefix-115/verify.py --out work/node115-snapshot-alternate-count-prefix-check-fresh.json
```
