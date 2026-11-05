# RE-001: resolve node115 non-ASCII startup text trimming

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The existing build-selection packet identifies this trim routine but limits its modeled behavior to ASCII. The forward pass decodes code points and records the byte offset of the first non-whitespace scalar. It admits ASCII 0x09 through 0x0d and 0x20, and classifies non-ASCII code points by their high byte. Page zero uses table mask 0x01 and page 0x20 uses table mask 0x02. Pages 0x16 and 0x30 accept only U+1680 and U+3000 respectively.

The reverse pass reconstructs scalars from the end up to the first retained scalar, applies the same classifier, and returns a borrowed pointer plus byte length. An all-whitespace input returns zero length. This closes the non-ASCII classifier and boundary selection; it assumes valid UTF-8 and makes no malformed-input or locale claim.

The retained 1 full FDEs cover 663 bytes and 175 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-unicode-trim-115/collect.py --out work/startup-unicode-trim-fresh
python3 -B research/work-items/RE-001-startup-unicode-trim-115/verify.py --out work/startup-unicode-trim-check-fresh.json
```
