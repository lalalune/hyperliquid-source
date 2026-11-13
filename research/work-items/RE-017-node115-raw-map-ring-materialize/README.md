# RE-017: raw pending ring materialization (#115)

## Question and scope

PR #6696 establishes how `0x515d620` prepares the records returned by `0x5b80560` but leaves that input conversion opaque. How are the pending map's wrapped 24-byte records supplied to the builder? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`.

## Selected observations

The builder copies the incoming four-qword descriptor and calls `0x5b80560` (`0x515d631..0x515d64c`). The helper reads its `+0x18` qword `C`, checks an allocation size bound and requests `24*C` bytes, then reads descriptor qwords at offsets `0`, `+8`, `+0x10` as capacity `N`, base pointer `P` and head `H` (`0x5b8056b..0x5b805d5`). These labels are inferred from the address arithmetic and #6688, not asserted source types.

Under `N>0`, `H<N`, `C<=N`, valid nonoverlapping allocations and normal resolved helper returns, it copies `min(C,N-H)` 24-byte records starting at `P+24*H`, then, if needed, copies the remaining `C-min(C,N-H)` records from `P` (`0x5b805d8..0x5b8067c`). Each iteration moves all 24 bytes via one 16-byte and one 8-byte load/store. It then calls slot `0x64df4a0` with the original base and `24*N` when `N` is nonzero, and returns `(C,new_pointer,copied_count)` (`0x5b8067e..0x5b8069a`). The indirect callee's semantics are not established here.

Consequently, under those assumptions the builder receives a contiguous sequence in the same logical order as #6688's wrapped traversal; #6696 separately analyzes a selected subsequent sort. Empty and error paths, aliasing, invalid ring metadata, actual runtime reachability, full builder equivalence, checkpoint restoration and state-root alignment remain open. No completion gate changes.

## Reproduction

Run `python3 research/work-items/RE-017-node115-raw-map-ring-materialize/verify.py` to authenticate the target, verify five instruction anchors and one direct call, and reject five independent one-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; `relocations.txt` uses `readelf -rW`. Python 3.11.15 was used. The target is not executed.
