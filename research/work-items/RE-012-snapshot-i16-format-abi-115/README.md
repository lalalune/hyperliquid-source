# RE-012: recover node #115 signed 16-bit decimal conversion and writer ABI

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The default formatting arm reads a 16-bit value, computes its unsigned magnitude using a 16-bit negate and conditional move, and determines the sign separately from the original word. That keeps the 0x8000 magnitude representable even though its signed positive counterpart is out of range. The decimal path splits at 1000 and uses the two-byte digit table at 0x46ea12 for successive remainder groups. In the smaller arm the zero top digit is omitted when the original value is nonzero, while zero itself retains a digit.

The dispatch gives flag 0x02000000 priority over 0x04000000 for hexadecimal. The default writer receives the nonnegative predicate, a zero prefix length and a backward-generated decimal slice. The hexadecimal writer instead receives a two-byte prefix at 0x4790cd (0x), a true sign predicate and its own backward-generated slice. Both invoke slot 0x64dfa00. The packet describes the signed-16 conversion and writer ABI.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-i16-format-abi-115/collect.py --out work/node115-snapshot-i16-format-abi-fresh
python3 -B research/work-items/RE-012-snapshot-i16-format-abi-115/verify.py --out work/node115-snapshot-i16-format-abi-check-fresh.json
```
