# RE-012: map node #115 formatter diagnostic slice bound

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the diagnostic slice bound reached from the quoted formatter's boundary-error calls. Slot 0x64df670 leads to 0x16806c0, which calls slot 0x64e1f00 resolving here. For input length at most 256, the routine stores the original pointer and length. For length at least 257, it starts at index 256 and searches backward, checking groups of up to four successive bytes against signed -65. Signed greater-than accepts byte values 0..127 and 192..255, excluding UTF-8 continuation bytes 128..191. The chosen index is stored as the new length and compared with the original length to set the truncation flag. This is a diagnostic display bound, not a full UTF-8 validation pass.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-format-diagnostic-bound-115/collect.py --out work/node115-snapshot-format-diagnostic-bound-fresh
python3 -B research/work-items/RE-012-snapshot-format-diagnostic-bound-115/verify.py --out work/node115-snapshot-format-diagnostic-bound-check-fresh.json
```
