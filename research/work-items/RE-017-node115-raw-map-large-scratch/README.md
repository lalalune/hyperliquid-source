# RE-017: raw pending rebuild large-record scratch (#115)

## Question and scope

PR #6696 maps the builder's 2–20 record preparation but excludes its `n>=21` helper. What scratch storage does that selected helper request? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`.

## Selected observations

At `0x515d776..0x515d781`, count `n>=21` is passed through slot `0x64e58f8`; the recorded relative relocation has addend `0x4f42e10`. The helper computes `ceil(n/2)` as `n-(n>>1)` and a scratch count `K = max(ceil(n/2), min(n,333333))` (`0x4f42e23..0x4f42e43`).

When `K<=170`, it uses the stack buffer and passes capacity 170; otherwise it requests `24*K` bytes from the indirect allocation slot and passes capacity `K`. For selected normal-return inputs the stack reserve is 4096 bytes, while 170 records use 4080 bytes. It supplies the scratch pointer, capacity, and a Boolean `n<65` to direct helper `0x4f97450` (`0x4f42e47..0x4f42eb1`). A size guard and allocation-error branches exist but their full behavior is outside this packet.

For example `n=170` selects stack scratch and `n=171` selects allocation; these boundary deductions assume normal nonoverflowing integer/address arithmetic and correctly resolved slots. This does not prove the helper sorts, preserves every payload, or is reached for a real pending map. Allocation failure, downstream helper semantics, checkpoint recovery and state-root equivalence remain open. No completion gate changes.

## Reproduction

Run `python3 research/work-items/RE-017-node115-raw-map-large-scratch/verify.py` to authenticate the target, verify four anchors and one direct call, and reject four independent single-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; `relocation.txt` uses `readelf -rW`. Python 3.11.15 was used. The captured target is not executed.
