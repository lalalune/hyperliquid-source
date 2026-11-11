# RE-012: map node115 account database home path fallback

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected home fallback asks sysconf selector 0x46 for
scratch size and substitutes 512 on a negative result.
Positive size allocates scratch storage and zero uses pointer
one. It calls getpwuid_r for getuid with that size and a
result pointer slot initialized to null. Nonzero status or
a null result selects the high-bit absence marker. There is
no local resize loop on that path.

A returned record supplies the directory pointer at +0x20.
The wrapper copies strlen bytes into owned storage, or uses
pointer one for an empty path. Nonzero scratch size is released
before output publication. The retained home-selection packet
covers the environment fallback edge. This packet follows the
account query, scratch lifetime and owned output layout.

The retained 1 full FDEs cover 490 bytes and 130 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 3 RELATIVE addends, 5 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-account-home-owned-result-115/collect.py --out work/account-home-owned-result-fresh
python3 -B research/work-items/RE-012-account-home-owned-result-115/verify.py --out work/account-home-owned-result-check-fresh.json
```
