# RE-017 · Node #115 verified Block queue publication and baseline advance

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Analysis base `6d9382f821930b10d181cb90fe4a32756fd8e069`. Addresses are linked ELF virtual addresses.

## Question

The [wait-loop packet](../RE-001-node115-nv-stream-execution-wait-loop/README.md) reaches the retained-buffer helper. The [queue publication](../RE-017-node115-replay-queue-publish/README.md) and [first-published-row](../RE-017-node115-replay-first-published-row/README.md) packets cover the shared queue primitive and an earlier selected Tx-shaped pair. On a normal completed Block batch, where do the two queued words come from, and when does the outgoing baseline advance?

## Observations

1. **Retained batch input.** At `0x5a89b16`, the outer worker passes the replay future F and a stack copy of its 32-byte retained descriptor to slot `0x64ebfc8`, whose relocation resolves to `0x5a81650`. On the selected validated path, `0x5a818ca` passes a three-word vector view and the word from F+0x110 to `0x4facd10`. The normal tag `0x2e` branch takes the vector's row address from result+0x10 and count from result+0x18. The next-address limit is row address plus `16 * count`. A zero count does not enter the row loop.
2. **Normal Block publication.** At `0x5a81955..0x5a81967`, the loop advances its local cursor by 16 and reads the old row's two qwords A/B. A is the valid Block owner on this selected route. The code reads A+0x60 when A+0x28 equals marker `0x8000000000000001`, otherwise A+0xb0, then computes the unsigned saturating increment of that word. On the selected queue reservation path Q is the pointer from F+0xc8. After a successful reservation, the two row qwords are staged unchanged at stack+0x70/+0x78 and sent in that order with the producer descriptor Q+0x80 to `0x581b0c0` at `0x5a819e7`.
3. **Baseline and completion.** The selected normal continuation after publication and notification stages stores the computed successor to F+0x110 at `0x5a81a48`. This is a different object field from the notification word Q+0x110. Then `0x5a81a4b..0x5a81a69` checks whether the saved next-address equals the vector limit and repeats when there is another row. On ordinary exhaustion, the result uses byte `0x44` and a signed-minimum leading descriptor word. The enclosing waiter recognizes that word at `0x5a89bc2` on its normal-result route.

The selected route requires the validated helper result, valid initialized row owners, successful queue reservation and normal helper/wake returns. Asynchronous consumption, root validation, consensus proof internals, unexpected result tags, complete queue concurrency and checkpoint progression remain separate contracts. This is the publisher's local baseline update. It makes no claim about when the replay consumer sees the updated field.

## Reproduction

```sh
python3 -B research/work-items/RE-017-node115-replay-block-publish-advance/verify.py
```

The [instruction spans](windows.txt) and [offline output](offline-log.txt) record the pinned ELF, indexed FDEs, and comparison with GNU and LLVM disassembly. The verifier checks the selected native calls, row strides and fields, saturating projection, store order and normal completion witness. Synthetic controls cover two distinct adjacent pairs and both marker projections. The target is read as ELF data.
