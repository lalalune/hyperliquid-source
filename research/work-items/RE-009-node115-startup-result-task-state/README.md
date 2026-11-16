# Startup result pointer reaches the task's state input

Target `node/115`: SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes. Static-only evidence; no target execution or emulation.

## Remaining question and contribution

`RE-009-abci-freeze-snapshot-115` establishes the task constructor's input `+0x320` to task/context state-slot path, but leaves that input's earlier producer unconnected. This packet binds it to a precise earlier startup result: on the selected normal success path, `0x2ad7140` result `+0x30` is copied through `0x2af45f0` result `+0x380` into the actual `0x2b3aba0` constructor input `+0x320`.

The contribution is pointer-value identity at this boundary. It does not identify `0x2ad7140`'s entire internal state machine or prove that the pointed-to state is restored, valid, immutable, live for all later uses, or the same instance produced by another loader.

## Prior attempts and separation of objects

- #6065 already identifies `0x2b41b70 -> 0x2af45f0`, spawning through `0x2b3aba0`, awaiting and returning a box. This packet supplies the missing field-level producer relation.
- #2181 / `RE-009-abci-freeze-snapshot-115` already establishes constructor input `+0x320 -> task+0x360`, dispatch through vtable `0x6449fb0 -> 0x2b1df60`, the `0x2d275d0` constructor input `+0x420 -> context+0x450`, and the later `0x2774590 -> 0x2d23610` end-selector path. Those are downstream contracts reused here.
- #6064 covers the latter context-constructor state input. It is not a proof of the earlier startup producer.
- #2047 / `RE-017-abci-loader-handoff-115` concerns a separate `0x3c12800` call inside `0x2b41b70` and storage at the middle object's `+0x40`.
- `RE-008-startup-initial-box-115` concerns the outer `0x2b41b70` result box, its storage by `0x2af0660`, and an outer result `+0x380` heading toward `0x5a6bfb0`. That `+0x380` belongs to a different object. It must not be conflated with the `0x2af45f0` result `+0x380` proved here.
- PR #7050 traces a different field through part of this startup path: the refresh-bypass tag at aggregate `+0x260`. It does not supply this state-pointer relation.

The `0x595ac30` checkpoint-result packet and its parent fields `+0x780/+0x788` are likewise not asserted to be this producer. Connecting those results requires further evidence.

## Native copy chain

Use A for the coroutine frame of `0x2af45f0`, O for its caller-provided result, and P for the middle object held in RBX by `0x2b41b70`.

1. At `0x2af4cf0..0x2af4d07`, `0x2af45f0` polls `0x2ad7140` with frame `A+0xf8`, writing a result to stack `+0x330`. Discriminant 3 is pending and exits this success path. The completed `0xa0` bytes are copied to stack `+0x640`; only discriminant 2 continues at `0x2af4d43..0x2af4d4b`.
2. `0x2af4d51` loads R15 from stack `+0x670`, i.e. completed result `+0x30`. Call this pointer value L. After the intervening selected path, `0x2af523a` stores L in stack `+0x10`. Later R15 is reused for unrelated values; the saved slot is the relevant carrier.
3. `0x2af5c23..0x2af5c28` loads that saved value and writes `O+0x380 = L`. The first `0x308` output bytes are copied separately. In particular, neither the tag at `O+0x308` nor the neighboring pointers at `O+0x3a8/+0x3b0` is L's carrier.
4. `0x2b41b70` calls `0x2af45f0` at `0x2b42429`, writing O to stack `+0x70`. Pending tag 2 exits before these moves. On completion, `0x2b42442..0x2b42454` copies `0x3b8` bytes from stack `+0x70` to `+0x430`.
5. `0x2b4246b` loads stack `+0x7b0 = 0x430 + 0x380`, then `0x2b42473` stores it at `P+0x50`. After the intervening selected cleanup, `0x2b42525` reloads R15 from `P+0x50` and `0x2b42597` stores it at `P+0x3a0`.
6. The actual task input starts at `I = P+0x80` (`0x2b42539`). Consequently `I+0x320 = P+0x3a0 = L`. `0x2b425f3..0x2b425fe` copies `0x350` bytes from I to stack `+0x70`, retaining this slot, and `0x2b4261c` calls `0x2b3aba0` with that copied input.

This is the input whose downstream task/context projection is already documented by the credited freeze packet. The proof is selected-path/static and uses the ordinary x86-64 ABI's callee-preserved registers. It does not assert that arbitrary aliased callees cannot mutate the pointee; retaining a pointer value is not a proof of retaining its contents or lifetime. Normal cleanup of prior frames and all error/unwind/retry paths remain separate contracts.

## Evidence and validation

`records.json` retains the complete FDEs for `0x2af45f0`, `0x2b41b70`, and the credited constructor `0x2b3aba0`: 2,785 instructions, 88 explicit instruction witnesses and the `memcpy` import binding. Keeping full functions makes surrounding stores and alternate branches reviewable; the conclusions apply only to the stated success path.

`verify.py` checks target identity, exact function bytes, FDE bounds, instruction transcription, selected witnesses and the import. Twelve negative controls reject a wrong target, wrong pending/success branches, an adjacent result field, wrong saved register, truncated output/constructor copies, a wrong input base and removal of the actual constructor call. It checks evidence consistency, not native execution or whole-program correctness.

The work item is registered with the research reproduction and catalogue tooling. Repository validation is recorded separately; no new speculative runtime implementation is introduced for the unresolved loader internals.
