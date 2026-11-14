# RE-017: raw pending-map rebuild small sort (#115)

## Question and scope

PR #6695 identifies the `0x515d620` builder used on a selected large flat-map insertion but leaves its preparation behavior opaque. How are its returned 24-byte records prepared before the tree-building helper? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. FDEs: `[0x515d620,0x515d7b9)` and `[0x53f0290,0x53f0330)`.

## Selected observations

The builder copies the incoming descriptor and calls `0x5b80560`, then reads the returned qword at `rsp+0x28` as count `n` and the pointer at `rsp+0x20` as its data. With `n=0` it takes the empty-result path; with `n=1` it bypasses the preparation calls; with `2<=n<=20` it calls `0x53f0290(data,n,1)`; with `n>=21` it calls slot `0x64e58f8` (`0x515d651..0x515d787`). The static relative relocation for the latter has addend `0x4f42e10`; that larger path is not analyzed here.

For the selected `2..20` case, the helper compares each record's first qword as unsigned against its predecessor and shifts records of stride `0x18` while the inserted key is strictly smaller (`0x53f02a3..0x53f032c`). It moves the key and its following 16 bytes together. Given valid writable nonoverlapping storage and normal execution, the loop is an insertion sort of the 24-byte records by unsigned key; equal-key records are not moved past one another. The builder subsequently allocates an `0xe8`-byte node and passes the prepared record range to `0x4cc28e0` (`0x515d678..0x515d6ec`).

This describes the small preparation path, not the large indirect helper, the downstream tree construction, full comparator/ownership semantics, real reachability or equivalence. Input validity, source-helper behavior, allocation and normal returns are assumptions. No checkpoint, state-root or completion claim is made.

## Reproduction

Run `python3 research/work-items/RE-017-node115-raw-map-small-sort/verify.py` to authenticate the target, check seven instruction anchors and four direct calls, and reject seven independent one-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; `relocation.txt` uses `readelf -rW`. Python 3.11.15 was used. The captured target is not executed.
