# RE-012: recover node #115 host libc version pair decoder

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The resolver error path calls a host-version decoder. Its first input is the host C library version, established by GLOB_DAT slot `0x64eca08` for `gnu_get_libc_version`; slot `0x64df698` obtains the returned string length with `strlen`. The pointer and length are passed with a stack result slot to RELATIVE target `0x16815e0` through `0x64dfca8`. Initial result tag 1 produces zero in the output tag slot.

The other path initializes a delimiter state with two ASCII dots and invokes `0x5ca9530` twice. The two decimal component paths reject empty tokens and standalone signs. For a longer token a leading plus is skipped; the digit gates subtract ASCII zero and check the unsigned result against nine. At 17 or more remaining bytes the accumulator uses unsigned multiply with overflow and checks carry from adding the next digit. The successful arm stores the two qwords at output offsets 8 and 16 and writes tag 1 at offset zero. Failure writes tag zero without clearing the component slots. This window covers the version-pair decoder, without assigning a version threshold to its caller.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-libc-version-pair-115/collect.py --out work/node115-snapshot-libc-version-pair-fresh
python3 -B research/work-items/RE-012-snapshot-libc-version-pair-115/verify.py --out work/node115-snapshot-libc-version-pair-check-fresh.json
```
