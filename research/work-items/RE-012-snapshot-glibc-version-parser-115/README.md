# RE-012: recover node #115 glibc version component parser

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The worker obtains the version string through gnu_get_libc_version at relocation slot 0x64eca08 and obtains its byte length through strlen. It sends the pointer and length to the helper at slot 0x64dfca8. Result tag one from that helper publishes zero in the output's first qword. The other path initializes a splitter with the dot delimiter and uses 0x5ca9530 twice to get candidate components.

The numeric paths check for a leading plus and validate ASCII decimal digits. In the second component the cutoff for selecting checked multiplication is 17 digits after accounting for that plus. The long loop checks both multiplication overflow and carry from adding the digit, then rejects either condition through the zero-result path. The successful publication stores the first and second parsed values at offsets 8 and 0x10 and writes one at offset zero. This packet covers the numeric conversion and result contract of this libc version consumer.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-glibc-version-parser-115/collect.py --out work/node115-snapshot-glibc-version-parser-fresh
python3 -B research/work-items/RE-012-snapshot-glibc-version-parser-115/verify.py --out work/node115-snapshot-glibc-version-parser-check-fresh.json
```
