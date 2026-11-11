# RE-012: map node #115 snapshot follow-up integer formatter

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The follow-up optional value calls 0x25fba40. This formatter has its own full unwind extent and output sites. It tests against 10,000, selects its tail with tests at 0x25fbae4 and 0x25fbb37, and checks the returned span bound against 20. This identifies the concrete callee for the follow-up path.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-followup-decimal-format-115/collect.py --out work/node115-snapshot-followup-decimal-format-fresh
python3 -B research/work-items/RE-012-snapshot-followup-decimal-format-115/verify.py --out work/node115-snapshot-followup-decimal-format-check-fresh.json
```
