# RE-012: recover node #115 shared UTF-8 validator and result layout

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

Existing RE-003, RE-005 and RE-015 records bind the shared byte-validation entry but leave its body as a boundary. The RE-012 host-version path reaches the same entry through slot `0x64dfca8`. This packet recovers the validator's scan and result layout.

The routine advances scalar ASCII bytes and, once aligned and sufficiently far from the end, skips groups of 16 using the OR of two qwords and a mask of their byte high bits. Non-ASCII lead bytes index the width table at `0x46ebe7`. Widths 2, 3 and 4 take distinct paths with length checks before each required byte and signed continuation checks implementing 0x80 through 0xbf. Special second-byte gates restrict E0 to A0–BF, ED to 80–9F, F0 to 90–BF and F4 to 80–8F. The ordinary lead-byte paths exclude the special leads and retain the ordinary continuation limits.

Tag zero returns the original pointer and length at output +8 and +16. Tag one instead stores the valid-prefix length at +8. The byte at +16 distinguishes truncation (zero) from a malformed sequence (one). For malformed input, +17 gives the number of bytes from the invalid sequence start to the first offending continuation, or one for a bad lead or first continuation. For truncation the length byte has no established meaning. These findings concern the shared validator body.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-shared-utf8-gate-115/collect.py --out work/node115-snapshot-shared-utf8-gate-fresh
python3 -B research/work-items/RE-012-snapshot-shared-utf8-gate-115/verify.py --out work/node115-snapshot-shared-utf8-gate-check-fresh.json
```
