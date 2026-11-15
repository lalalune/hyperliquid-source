# Node #115 tracker prefix: 32-byte lookup and projection

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This is static evidence on one path following the separately traced threshold split.

The flat prefix cursor reads an 80-byte-stride row and stages its contents; on the selected continuation, `0x5377390` calls `0x57f93d0` with a descriptor at stack +0x130 and a pointer at stack +0x151. The result's low flag and returned index are checked: nonzero flag or index >= descriptor count skips the following projection. For a found entry, `0x53773bb..0x53773ef` adds the descriptor head to the index, subtracts the descriptor capacity once if needed, and addresses the selected 96-byte-stride record at base + 96*slot + 0x20.

For a valid nonwrapped descriptor with 32-byte lexicographically sorted unique keys at the start of each 96-byte row, `0x57f9462..0x57f950a` searches the contiguous range by 32-byte comparisons and returns flag 0 and the matching logical index, or flag 1 and an insertion index if absent. Empty input returns flag 1. The indirect comparison slot `0x64dfb50` has the pinned ELF relocation `memcmp@GLIBC_2.2.5`. The full descriptor construction, semantics of the compared bytes, wrapped search, target runtime binding, malformed metadata, and downstream record processing are not claimed.

Run `python3 research/work-items/RE-017-node115-tracker-prefix-hash-lookup/verify.py` to authenticate the target, validate instruction and direct-call anchors, and reject mutations without target execution. Disassembly and relocation are in `windows.txt`.
