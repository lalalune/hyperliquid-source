# RE-001: map node115 gossip address octet digit bounds and partial stores

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The dotted-address wrapper delegates three octets to this bounded writer. Values below ten use one ASCII store. Ten through 99 use a decimal table pair, with a check before each indexed destination byte. Values from 100 use a multiply/shift hundreds digit and the table pair for the remainder. The successful return is the number of bytes stored.

The capacity checks precede each store individually, so a short destination can contain earlier digits before the later bound failure. The packet distinguishes those partial stores from successful one-, two- or three-byte returns and preserves the table and failure branches.

The retained 1 full FDEs cover 290 bytes and 73 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-address-octet-capacity-115/collect.py --out work/gossip-address-octet-capacity-fresh
python3 -B research/work-items/RE-001-gossip-address-octet-capacity-115/verify.py --out work/gossip-address-octet-capacity-check-fresh.json
```
