# RE-001: map node115 child read probe before buffer growth

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The child reader delegates its low-spare-capacity path to this 32-byte stack probe. It zeroes the scratch buffer and reads into that buffer before comparing the returned count with the vector spare capacity. When data fits, it copies only the returned byte count. When it does not fit, it first reserves room using the returned count and reloads the vector length before copying. EOF leaves the vector length unchanged.

On read -1 the wrapper retries errno four using the same scratch buffer. Other errno values return the packed high-word errno with low tag two as the error payload. The count guard rejects values above 32 before the vector copy path. The main reader loop and its request sizing are separate from this one-probe contract.

The retained 1 full FDEs cover 321 bytes and 89 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-child-read-probe-115/collect.py --out work/startup-child-read-probe-fresh
python3 -B research/work-items/RE-001-startup-child-read-probe-115/verify.py --out work/startup-child-read-probe-check-fresh.json
```
