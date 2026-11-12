# RE-017: selected flat pending removal on missing digest (#115)

## Question and scope

PR #6677 identifies flat pending-map digest extraction; #6678 shows that zero callback returns are compacted out. What happens for a concrete missing-digest case? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`.

## Conditional path

Assume a valid flat pending map containing exactly one record, a primary timer comparison selecting extraction, and a tracker whose digest lookup structure at `+0x18` is the sentinel `0x8000000000000000` with null root at `+0x20`. Under these assumptions `0x5377df0` follows `0x5377e19..0x5377e30` to `0x5377fdf`, which writes sentinel `0x8000000000000001` as its result. The callback compares that result and branches to its return-zero path without appending a row (`0x57d467f..0x57d46a6`, `0x57d4a48`).

The flat scan tests the callback's low byte (`0x57f16f7..0x57f16fe`). For the stated one-record case, zero reaches the end-of-scan path with retained count zero, and the map `+0x18` qword is written as zero (`0x57f171c..0x57f1723`, `0x57f183e..0x57f1848`). Thus a missing selected digest can remove that pending record on this specific static route, without a corresponding queued row. #5157 documents the extraction failure sentinel; this packet connects that result to the distinct flat-map compaction in #6678.

This does not establish whether the scenario is reachable or valid in production, whether other data sources reconstruct the result, or any security or loss consequence. Correct pointers, no alias interference, a valid ring and normal calls are assumptions. Other extraction failures and multi-entry scheduling are outside this focused case. No checkpoint, state-root or component-completion claim is made.

## Reproduction

Run `python3 research/work-items/RE-017-node115-flat-missing-digest-removal/verify.py` to authenticate the target, verify six instruction anchors and two direct calls, and reject six independent single-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; Python 3.11.15 was used. The target is not executed.
