# Node #115: tracker 20-byte large-sort run discovery

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static evidence extending the separately traced 20-byte large-sort scratch allocation.

The large-sort helper calls `0x3e4aa90` at `0x36e2f70`. For 2<=n<4097, `0x3e4aaea..0x3e4ab00` computes `T=min(ceil(n/2),64)`. For n>=4097, with `k=ceil(floor(log2(n|1))/2)`, `0x3e4ab07..0x3e4ab2c` computes `T=floor((2^k+floor(n/2^k))/2)`.

On a selected segment with at least T remaining entries, `0x3e4ac4d..0x3e4acdc` compares 20-byte adjacent keys via slot `0x64dfb50`, whose pinned ELF relocation identifies `memcmp@GLIBC_2.2.5`. The first comparison selects a nondecreasing or strictly decreasing scan; the nondecreasing branch continues while adjacent comparisons are >=0 and stops when the next element is smaller. Each step advances 20 bytes. The strictly decreasing branch, later merging, short segments, imported-function runtime binding and actual production inputs are not claimed by this packet.

Run `python3 research/work-items/RE-017-node115-tracker-key-sort-runs/verify.py` to authenticate the target and validate instruction/direct-call anchors and mutation controls without executing the target. Disassembly and relocation are in `windows.txt`.
