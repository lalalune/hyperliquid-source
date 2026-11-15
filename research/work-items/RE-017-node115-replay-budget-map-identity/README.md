# RE-017: selected replay timer budget and map counter identity (#115)

## Question and scope

PR #6626 binds the timer budget to the initial tracker `+0x78` qword, while #6624 shows a separate decrement through the traversal descriptor but leaves that pointer's owner unknown. Are they the same field on the selected caller path? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`.

## Static observation and conditional consequence

At `0x5afa044` the caller passes `tracker+0x60` as the first argument to `0x4de0540` and independently snapshots `tracker+0x78` for the saturated `max(0,C-1000)` budget (#6626). The callee preserves that first argument in `rbx` (`0x4de0550`). On the selected sentinel route documented in #6626, it constructs a traversal descriptor at `rsp+0x28` whose `+0x08` is `rbx+0x18` (`0x4de0751..0x4de075f`) and calls `0x51520f0` with that descriptor. In its nonempty traversal case, the latter saves the descriptor in `r14` (`0x5152126`); its shared tail loads descriptor `+0x08` and decrements the pointed-to qword (`0x51527e9..0x51527ed`). Therefore the qword decremented on that selected path is `tracker+0x60+0x18 = tracker+0x78`, the same field from which the initial budget was computed.

The secondary comparison uses a separately initialized counter, initially zero, and the snapshot budget; when counter is below budget, `0x515269d..0x51526a3` increments it and jumps to the shared decrement tail (#6624). Let the initial unsigned qword be `C` and `B=max(0,C-1000)`. If exactly `k` such secondary operations occur, each reaches the decrement once, and no other path, helper, alias or concurrent operation modifies either qword, then for `0<=k<=B` the secondary counter is `k` and the target qword is `C-k`. At `k=B`, it is `min(C,1000)`. These conditions are essential: primary digest-extraction paths can also reach the shared tail, the loop may stop earlier, and this packet does not claim that all entries are pruned or that a universal 1000-entry floor holds. The interpretation of this qword as a map size is plausible from the dataflow but not required or proved by the arithmetic.

No live reachability, full traversal/helper semantics, checkpoint height, finality, or state-root alignment is established. No completion gate changes.

## Reproduction

Run `python3 research/work-items/RE-017-node115-replay-budget-map-identity/verify.py` to authenticate the target, verify seven instruction anchors and two direct calls, and reject seven independent one-byte mutations. `windows.txt` is Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel` output; Python 3.11.15 was used. This is static analysis and does not execute the target.
