# Node #115: reverse strictly descending 20-byte key runs

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static evidence extending the separately traced tracker-key large-sort run discovery.

The selected descending path compares successive 20-byte keys through slot `0x64dfb50`, identified by the pinned ELF relocation as `memcmp@GLIBC_2.2.5`. At `0x3e4ad10..0x3e4ad30` it extends a descending run only while each next key compares strictly less than its predecessor; equal keys terminate that run. When the selected run reaches the threshold, `0x3e4ad48..0x3e4adb3` reverses it by swapping two qwords and one dword per pair. Pointers advance and retreat by 20 bytes and the loop performs floor(length/2) swaps.

Under a valid buffer and ordinary named import behavior, full 20-byte values are reversed and equal adjacent values are not reversed within this descending run. The short-run path, later merge behavior, global sort stability, runtime binding and live reachability remain open.

Run `python3 research/work-items/RE-017-node115-tracker-key-descending-reverse/verify.py` for target digest, instruction anchors and mutation controls without target execution. Disassembly and relocation are in `windows.txt`.
