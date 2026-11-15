# Node #115: selected 24-byte ring moves with both sides wrapped

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; FDE `0x58127f0..0x5812ac5`. Static analysis, bounded to valid nonaliasing ring storage and the two branches below.

Let C>0, 0<=s,d<C, 0<n<=C, s!=d, s+n>C and d+n>C. Let ks=C-s and kd=C-d. Source and destination both cross the ring boundary; every index and count below is scaled by 24 bytes.

* For d>s, `0x5812847..0x58128c4` requests three moves in order: source 0 to destination d-s for n-ks records; source C-(d-s) to destination 0 for d-s records; source s to destination d for kd records.
* For d<s and n<=C+d-s, `0x5812945..0x58129a9` requests: source s to destination d for ks records; source 0 to destination d+ks for kd-ks records; source kd-ks to destination 0 for n-kd records.

The indirect calls/tail jump use slot `0x64df568`, identified by the pinned ELF relocation as `memmove@GLIBC_2.2.5`. The copy sequence preserves the selected logical source ordering if the import behaves as named. The d<s and n>C+d-s branch, invalid metadata, runtime binding and actual reachability remain open.

Run `python3 research/work-items/RE-017-node115-ring-move-both-wrap/verify.py` for target digest, instruction anchors and mutation checks without executing the target. Disassembly and relocation appear in `windows.txt`.
