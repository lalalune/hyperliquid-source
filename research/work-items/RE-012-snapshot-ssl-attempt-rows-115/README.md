# RE-012: recover node #115 SSL attempt row traversal and writer status

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The SSL payload formatter walks fixed-width attempt rows. The loop advances its row pointer by 0x48 and decrements its byte budget by 0x48. A writer failure is carried in the low status bit and suppresses later row emissions while the traversal reaches its common exit.

The ordinary arm writes a two-byte separator through writer slot +0x18 and sends the current row to RELATIVE formatter 0x5bacbc0 through slot 0x64dffd8. The alternate arm selected by formatter flag 0x80 builds a stack writer context using table 0x64078f8 and calls the same row formatter before its separate two-byte suffix. This maps sequence traversal and failure propagation. The individual row formatter and error-category dispatch are separate boundaries.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-ssl-attempt-rows-115/collect.py --out work/node115-snapshot-ssl-attempt-rows-fresh
python3 -B research/work-items/RE-012-snapshot-ssl-attempt-rows-115/verify.py --out work/node115-snapshot-ssl-attempt-rows-check-fresh.json
```
