# RE-012: recover node #115 Io and Ssl error formatting dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The formatter loads a pointer from its first argument and compares the pointee's first qword against zero using the overflow flag. Signed minimum takes the Io arm, which writes the two literal bytes from 0x7e03dc and advances the payload pointer by eight. Other first words take the Ssl arm, which writes three literal bytes from 0x7e03b2.

Each arm checks the initial writer status before inspecting formatter flag 0x80. In the compact branches, each writes a one-byte opening parenthesis and then invokes a different payload formatter: Io uses RELATIVE target 0x5ca7ea0 via 0x64e1878, while Ssl invokes 0x475b9e0 with the address of the saved object pointer. Nonzero status from the opening write bypasses the payload call. This recovers the tagged formatting dispatch and its direct payload boundaries.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-io-ssl-format-dispatch-115/collect.py --out work/node115-snapshot-io-ssl-format-dispatch-fresh
python3 -B research/work-items/RE-012-snapshot-io-ssl-format-dispatch-115/verify.py --out work/node115-snapshot-io-ssl-format-dispatch-check-fresh.json
```
