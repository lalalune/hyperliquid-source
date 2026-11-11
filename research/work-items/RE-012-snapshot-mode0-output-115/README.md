# RE-012 snapshot mode-0 output worker

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF VAs.

The merged snapshot selector evidence reaches 0x26a5100 for workers 0 and 3 when the received mode differs from 1. This packet follows that callee and distinguishes its fallback writer initialization from the mode-1 fallback in PR #3566.

At 0x26a5273 the mode-0 worker requests 128 bytes. When allocation succeeds it initializes the writer length to zero and the observed descriptor fields at stack +0x80/+0x88/+0x90 to 2/0/0. The mode-1 fallback initializes a different descriptor and emits a textual prefix before entering the shared serializer. The selected mode-0 path instead hands a fresh writer to the serializer at 0x2529970.

The worker constructs a collection descriptor before that call. NEG on the source's first word selects the alternate path exactly for 0x8000000000000000. On the other path three offsets are scaled by 96 and added to the source base. The serializer result is checked for nonzero before the worker reads the buffer for the next handoff. Separately, it tests the buffer's first word for 0x8000000000000000. The complete serializer, output schema and filesystem effects remain unresolved.

One full FDE spans 1,181 bytes and 295 instructions. GNU, LLVM and Capstone agree on instruction partitions. GNU readelf confirms the FDE. The verifier rejects four altered instruction windows, two RELATIVE addend changes and two input identity changes. The node was examined statically. Collector scaffolding is adapted from the MIT Build ID packet via the mode-1 packet.

From the repository root with authenticated inputs and versions in tools.json, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-snapshot-mode0-output-115/collect.py --out work/snapshot-mode0-fresh
python3 -B research/work-items/RE-012-snapshot-mode0-output-115/verify.py --out work/snapshot-mode0-check-fresh.json
```
