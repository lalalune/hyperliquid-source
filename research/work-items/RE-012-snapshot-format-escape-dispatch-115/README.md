# RE-012: map node #115 quoted escape dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the initial escape selector called from the quoted formatter at 0x16898c3. Unsigned inputs through 0x27 index a 40-entry table of signed relative offsets at 0x46d6cc. The target is table base plus the selected offset. Outside that range, 0x5c writes two backslashes directly. The remaining path tests the conjunction of input >= 0x300 and the low bit of the third argument. Only when both conditions hold does it invoke slot 0x64e1ea0 with the input value. A zero result selects the fallback at 0x167d34b, while nonzero enters the selected hex-digit extraction using 0x455d40. This packet pins the dispatch and predicate, without interpreting the indirect classification function or claiming the complete output encoding.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-format-escape-dispatch-115/collect.py --out work/node115-snapshot-format-escape-dispatch-fresh
python3 -B research/work-items/RE-012-snapshot-format-escape-dispatch-115/verify.py --out work/node115-snapshot-format-escape-dispatch-check-fresh.json
```
