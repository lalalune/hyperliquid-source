# Node #115: 24-byte ring movement with wrapped source

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; FDE `0x58127f0..0x5812ac5`. This is a bounded static analysis complementing the separately documented destination-wrap case.

Assume C>0, 0<=s,d<C, n>0, s+n>C and d+n<=C. Let k=C-s and r=n-k. The source wraps, destination is contiguous and s>d. The helper computes forward ring distance delta=C+d-s and compares it with n.

* If delta<n, `0x58129dd..0x5812a22` first requests moving r records from source 0 to destination d+k, then k records from source s to destination d.
* If delta>=n, `0x5812a6c..0x5812ab2` requests those moves in reverse order.

Each length and offset is multiplied by 24. Both calls use slot `0x64df568`, identified in the pinned ELF relocation table as `memmove@GLIBC_2.2.5`. This gives the copy order under the stated assumptions; it does not establish runtime import binding, both-sides-wrap behavior, malformed inputs or production reachability.

Run `python3 research/work-items/RE-017-node115-ring-move-source-wrap/verify.py` for whole-target digest, byte anchors and anchor mutation controls without executing the target. `windows.txt` contains the selected disassembly and relocation.
