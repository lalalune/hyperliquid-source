# RE-012: recover node #115 bounded UTF-8 code point append

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The staging writer's table slot at 0x6408058 resolves to this code-point append function. It produces one through four bytes, splitting the input at 0x80, 0x800 and 0x10000. The multibyte paths encode the continuation groups as 0x80 OR the corresponding low six bits and construct the leading byte from the remaining high bits. No scalar-validity predicate is visible in this function.

The writer adds the encoded length to the count at state +0, rejecting either unsigned carry or a sum at least 59. Only on success does it call memcpy to state +8+old_count and then publish the new count. It returns zero on success and one on rejection. This maps the append-side capacity check and mutation order, separate from the enclosing wrapper's final flush gate.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-staged-codepoint-append-115/collect.py --out work/node115-snapshot-staged-codepoint-append-fresh
python3 -B research/work-items/RE-012-snapshot-staged-codepoint-append-115/verify.py --out work/node115-snapshot-staged-codepoint-append-check-fresh.json
```
