# RE-017: selected timer counter origin (#115)

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are ELF virtual addresses. This follows the timer comparison in #6623 and counter update in #6624, and the selected tracker handoff in #5157. It does not establish checkpoint-height semantics or complete the replay gate.

## Static finding

`0x5afa030` reads the unsigned qword at tracker `+0x78`, computes `max(0, qword-1000)` by a subtraction and conditional move, and initializes a separate stack qword to zero. It constructs a seven-word context whose `+0x28` points at the zero and whose `+0x30` points at the saturated subtraction result, then calls `0x4de0540` with the tracker map at `+0x60` and that context.

On the selected `0x4de0540` path where `0 - [map]` sets overflow (the map qword has the bit pattern `0x8000000000000000`), the helper copies all seven context words to its own stack. It builds the traversal descriptor with the copied context pointer and calls `0x51520f0`; that callee loads the context pointer from descriptor `+0`. At `0x5152495`, the timer branch dereferences the two context pointers and performs the unsigned comparison described in #6623 and #6624. Under normal calls without aliasing or intervening mutation of the two stack qwords, their initial values at this selected drain invocation are therefore zero and `max(0, tracker[+0x78]-1000)` respectively. For tracker values at most 1000, the strict less-than comparison cannot be true initially. Above 1000 it can be true initially. This is a conditional dataflow observation, not proof that the earlier timer eligibility conditions hold.

The prior handoff packet identifies the tracker, selected callback and state ownership but explicitly leaves timer eligibility open. PR #6046 documents the analogous threshold for a different tracker drain (`0x5afa1f0`); the present packet ties this drain's two actual stack pointers through the selected `0x4de0540` call chain to the secondary timer comparison. It does not assume the two trackers are the same.

## Reproduce and limits

Run `python3 research/work-items/RE-017-node115-replay-budget-origin/verify.py`. It authenticates the ELF and checks five instruction anchors, two direct calls and five one-byte negative controls. `windows.txt` is from `/usr/bin/objdump -d --x86-asm-syntax=intel` with the recorded address bounds. This does not execute the target. The other `0x4de0540` path, timer arithmetic, runtime aliasing, the meaning of `tracker+0x78`, complete pruning behavior, real checkpoint data, roots and live-node equivalence remain outside the finding.
