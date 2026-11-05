# RE-001: map node115 child output drain and wait handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The shell output adapter delegates to this child collector. After the child creation helper, the collector separates its error tag and takes ownership of descriptors, resetting moved descriptor slots to -1. It creates two empty output buffers. With both capture descriptors present it enables nonblocking mode with ioctl 0x5421 and polls two eight-byte records for input with an infinite timeout. A failed poll reloads errno and retries on four. When one reader finishes, the other is returned to blocking mode before the final drain. With a single present descriptor the collector takes a direct drain and close path.

The wait helper runs after ordinary drain completion. The success arm publishes two three-word buffer records and the status word at +0x30. The wait-error arm releases allocated buffers and returns the high-bit error sentinel. This connects the caller status check to descriptor collection without interpreting host wait behavior or asserting runtime equivalence.

The retained 1 full FDEs cover 1483 bytes and 339 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 6 instruction/data windows, 2 RELATIVE addends, 4 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-child-output-drain-115/collect.py --out work/startup-child-output-drain-fresh
python3 -B research/work-items/RE-001-startup-child-output-drain-115/verify.py --out work/startup-child-output-drain-check-fresh.json
```
