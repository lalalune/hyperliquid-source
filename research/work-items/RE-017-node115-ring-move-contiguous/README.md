# Node #115: nonwrapped 24-byte ring movement

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. FDE `0x58127f0..0x5812ac5` is a static lead; the independently reported raw-map insertion calls this helper at `0x57ec781` and `0x57ec7b2` but leaves its behavior open.

The helper takes ring capacity C, backing pointer P, source slot s, destination slot d and record count n in the first five integer argument registers. It returns immediately if s=d or n=0 (`0x58127fb..0x581280a`). For C>0, 0<=s,d<C, n>0, s!=d and n<=min(C-s,C-d), `0x5812826..0x581282c` and `0x58128d8..0x58128de` choose `0x58129ae`, which tail-calls slot `0x64df568` with destination `P+24*d`, source `P+24*s`, and byte count `24*n`.

The pinned ELF relocation identifies that slot as `memmove@GLIBC_2.2.5`. If runtime binding behaves as this import and the buffer is valid, overlapping contiguous records are moved with memmove semantics. This does not establish wrapped cases, invalid metadata, growth behavior, actual runtime binding, or node equivalence.

Reproduction: `python3 research/work-items/RE-017-node115-ring-move-contiguous/verify.py` authenticates the target, checks byte and direct-call anchors, and rejects mutated anchors without executing the binary. `windows.txt` captures the disassembly and dynamic relocation.
