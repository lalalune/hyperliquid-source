# RE-017: raw pending write and drain clock source (#115)

## Question and scope

PR #6693 traces an existing pending value to the producer's second argument `+0x60`; #5157 traces the later selected drain but does not connect those input fields. Where are the write-side value and flat callback's comparison input obtained? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`.

## Selected dataflow

The selected dispatcher case at `0x54cb062..0x54cb078` passes `state+0x3e50` as tracker and the state itself as second argument to `0x5afa3b0`. The producer forms `state+0x60` and passes that pointer to the pending-map update (`0x5afa415..0x5afa421`, `0x5afa4b5..0x5afa4cb`). #6693 establishes that the selected existing-key update copies the 12 bytes through this pointer. The dispatcher routes to this case through its selector table; #6048 covers the table, not this twin's value replacement.

On the separately selected finalization path, `0x548becd` forms a pointer to state `+0x60`. Immediately before calling `0x5afa030` with tracker `state+0x3e50`, it copies the qword and following dword from that field to a 12-byte stack object (`0x548bf18..0x548bf4b`). The drain stores a pointer to that object at callback context `+0` (`0x5afa071`); on the flat branch, #6677 identifies the callback and `0x57d4503` reads this context pointer for its three-word comparison.

If both calls act on the same state instance, the write-side pending value and the later comparison input derive from the same field location, sampled at their respective calls. The values need not be equal because the state may change between calls; this does not show a time delta, valid date encoding, timer eligibility, chronological monotonicity, real runtime reachability, or checkpoint/root correctness. Existing-key lookup, valid pointers, no interference during each copy and normal calls are assumptions. No completion gate is advanced.

## Reproduction

Run `python3 research/work-items/RE-017-node115-raw-pending-clock-source/verify.py` to authenticate the target, verify eight instruction anchors and four direct calls, and reject eight one-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; Python 3.11.15 was used. The target is not executed.
