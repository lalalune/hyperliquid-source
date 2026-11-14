# RE-017: flat pending digest queue row (#115)

## Question and scope

PR #6677 connects the non-sentinel flat pending-map path to selected digest extraction but leaves its success output open. Does that path append the same key and selected digest to the tracker's output vector? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses. Main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. The callback FDE is `[0x57d44d0,0x57d4aea)`.

## Observations

`0x5afa066..0x5afa07f` places `tracker+0x48` in callback context `+0x10`. On the selected flat primary threshold path, the callback passes the saved entry key and context `+8` tracker to `0x5377df0` (`0x57d467f..0x57d4698`). The extracted result is tested against the `0x8000000000000001` sentinel; the sentinel route returns zero without this append. On the non-sentinel route, selected parts of the result are preserved on the stack, and the callback calls `0x5b7a830` and `0x4dc0330` before loading the output descriptor from context `+0x10` (`0x57d46ac..0x57d498c`). The semantics of those two helpers are not proven here.

`0x57d49bf..0x57d4a44` constructs and appends one `0x68`-byte row: the saved entry key at row `+0`; 32 bytes returned by `0x4dc0330` at `+8`; 32 preserved result bytes at `+0x28`; and the 32 result bytes initially at extraction-output offsets `+0x40..+0x5f` at row `+0x48`. #5157 separately establishes the selected digest's location in the extraction result and the tree route's downstream row. Thus, subject to that dependency and normal helper returns, this flat path preserves the same selected key and digest positions in the tracker output vector. The vector growth slot and helper failure paths are not characterized.

Valid context, allocation and vector state, no alias/interference and normal calls are assumptions. This is static evidence of a selected path, not proof of real replay reachability, authentication, checkpoint-height identity or state-root alignment. No completion gate is advanced.

## Reproduction

Run `python3 research/work-items/RE-017-node115-replay-flat-queue-row/verify.py` to authenticate the target, check seven instruction anchors and three direct calls, and reject seven independent one-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; `relocation.txt` records `readelf -rW`. Python 3.11.15 was used. No captured code is executed.
