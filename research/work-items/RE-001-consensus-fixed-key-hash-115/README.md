# RE-001: map node115 listener 20-byte key hash initialization and finalization

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The two listener key containers use this fixed-width hash adapter. It loads a 16-byte state input, duplicates the low and high halves separately and XORs them with two retained vector constants. It zeroes the trailing local words before passing the state and 20-byte key to a separate update helper.

On return, it combines a shifted length-like word and the saved tail, injects them into the state, then performs the retained add, rotate and XOR sequence with a separate 0xff finalization step. The packet binds the fixed input width and finalization without inferring the untraced update helper or claiming a cryptographic property.

The retained 1 full FDEs cover 325 bytes and 83 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-consensus-fixed-key-hash-115/collect.py --out work/consensus-fixed-key-hash-fresh
python3 -B research/work-items/RE-001-consensus-fixed-key-hash-115/verify.py --out work/consensus-fixed-key-hash-check-fresh.json
```
