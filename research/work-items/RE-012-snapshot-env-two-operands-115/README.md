# RE-012: recover node #115 environment setter operand preparation

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The environment setter entry stages name and value independently. Each operand whose length is at most 383 is copied into a separate 384-byte stack region and terminated at its original length. The search includes the synthetic terminator, so the operation proceeds only if the first zero is exactly at the original length. An interior NUL returns the fixed error descriptor before the writer call. After name validation the wrapper retains its pointer and terminated length in a stack context.

Long operands dispatch to the converter at 0x5c78ed0. The long-name path installs 0x5c81a80 as continuation, passing the original value descriptor. The long-value path instead installs 0x5c80b30 with the validated name context. When both operands fit inline, the wrapper calls 0x5c80b30 directly only after the second exact-terminator check. This maps the two-operand preparation and callback topology prior to the separately analyzed environment mutation.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-env-two-operands-115/collect.py --out work/node115-snapshot-env-two-operands-fresh
python3 -B research/work-items/RE-012-snapshot-env-two-operands-115/verify.py --out work/node115-snapshot-env-two-operands-check-fresh.json
```
