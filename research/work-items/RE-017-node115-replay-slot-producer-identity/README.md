# Replay slot producer and consumer share the constructed owner

Target: node/115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, size 105896032. Static ELF/FDE, relocation, jump-table and instruction data-flow only. No captured execution or emulation.

## Gap and prior work

#3980 (`RE-001-node115-nv-broadcast-channel-capacity`) establishes constructor `0x5964590`, power-of-two capacity and the identical owner pointers in its two outputs; its send/receive-position semantics remain open. #6767 and `RE-017-node115-replay-cursor-descriptor-origin` connect the replay reader descriptor and its cursor to the 48-byte slot lookup. #6766 connects a successful slot to its two payload words and downstream handling. These are prerequisites, not new constructor or consumer claims.

The missing link is the producer: does the task that writes the two words actually hold the same owner allocated for that reader, and where does its pair come from? This packet closes that link for the selected task-construction branch. It enables a downstream replay fixture to use the actual writer/reader storage relation while keeping the opaque payload-decoder and checkpoint-height relation explicit. It does not establish checkpoint height plus one, a trusted expected root or a live replay result.

## One allocation, two handles

Let F be the replay future in `0x5a82670`. At `0x5a861b3`, it calls the existing constructor with requested capacity 1000. The constructor returns `(A, A, 0)`: the same allocation A in output+0 and +8, with an initial reader cursor zero in +0x10. It also initializes the producer sequence at A+0x30 to zero as part of the zero store at `0x596463b`. Capacity normalization and slot initialization are credited to #3980; allocation success is assumed here.

The caller retains the first A in RBP at `0x5a861b8`, and copies the second `(A,0)` into F+0x178/+0x180 at `0x5a861c8` / `0x5a861d1`. It constructs task bytes T at stack+0x2320: after the first 0x98 bytes, `0x5a86242` writes the first A at `T+0x98` and initializes the task state byte at T+0x918 to zero.

`0x5a86288` is a **destruction branch**, not task publication. The selected valid-context path instead reaches `0x5a86cd4` and later copies the 0x920-byte task image T to stack+0x3190 at `0x5a86d57`. For the branch selected by `R12 == 1`, `0x5a86d76` passes that image to `0x5aa6f70`, which preserves RSI through its call to `0x5965560` at `0x5aa6f98`. The alternative task-construction branch is outside this claim.

## Constructor installs the writer's actual future

Inside `0x5965560`, the task input is copied to local stack+0xab0. A second copy from stack+0xaac to stack+0xb4 includes four bytes before that task; consequently the task itself lands at stack+0xb8. Copying the final object image from stack+0x80 to allocated object H puts the task at `W = H+0x38`.

The same constructor stores vtable address `0x64ba160` at H+0x10. Its poll entry relocation is `0x5a950f0`, whose selected poll branch passes H+0x38 to `0x5a806f0` at `0x5a95299`. Thus the writer future W receives the previously constructed image with `*(W+0x98) = A`; matching shapes alone are not used to infer identity.

The writer's initial-state jump table at `0x939a34` maps state 0 to `0x5a80ef9`. That path sets W+0xa8 to **the address** W+0x98, and `0x5a808d8` saves that address at W+0xb0. At the write call `0x5a80ede`, RSI is therefore `&W[0x98]`, a pointer to the handle, not A directly. The first load in `0x5963aa0`, at `0x5963ab1`, dereferences it and recovers exactly A. The packet does not claim when the scheduler chooses to poll H.

## Pair origin and slot store

On the selected successful decoder branch, `0x5a80de7` calls `0x5860bb0` and requires result byte `0x12`. It loads result+8 and result+0x10 into R15 and R14 at `0x5a80dfa` / `0x5a80e02`. After intervening cleanup and timing calls, the branch selected by cleared R12 copies those same words to stack+0x30/+0x38 and passes their address to the slot writer. These words are not assigned block, height or root meanings here: `0x5860bb0` remains an opaque semantic dependency.

On the normal write branch, `0x5963aa0`:

1. Locks A+0x28 and requires the nonzero value at A+0x38. If it is zero, it returns the supplied pair through the error arm without performing this write.
2. Reads producer sequence q from A+0x30, advances that sequence, and chooses index `A.mask & q` using A+0x20. It bounds that index by A+0x18.
3. Computes `S = *(A+0x10) + 48 * index` and locks the slot.
4. Stores q at S+0x28 and the captured A+0x38 count at S+0x20. If the old slot tag is nonzero, it drops that old payload through existing helper `0x5956b80` before replacing it.
5. Stores tag 1 at S+8, copies the exact 16-byte supplied pair to S+0x10/+0x18, then releases the slot lock and invokes the existing notification/unlock helper.

This is the normal-return store path with the helper contracts assumed; it is not a proof of the entire concurrent channel, wakeup behavior, every unwind path, or lag policy.

## Join to the actual reader descriptor

The reader path retains `D = &F[0x178]`, whose first word is the same A. It puts D at F+0x1c8 (`0x5a86e91`), separately zeroes F+0x1d0, and calls `0x59d6520` with F+0x1c8 at `0x5a86f90`. The wrapper dereferences that pointer and passes D to `0x59640e0`. That reader loads A from D and uses **D+8** as cursor C, rather than the separate F+0x1d0 field.

Reusing #6767, the reader computes the same storage formula `S = *(A+0x10) + 48 * (A.mask & C)`, locks S and tests S+0x28 against C. For a matching sequence, it increments D+8 and returns tag 3 with the exact locked S. Reusing #6766, `0x59d6520` observes tag 1 at S+8, retrieves the two words S+0x10/+0x18, retains the required references and returns their values in its output pair.

The construction makes initial q and initial C both zero. Therefore, **conditional on** a successful producer write at q=0 remaining the slot's current matching sequence when the reader acquires it, the reader's matching branch selects the producer's exact slot and two words. This conditional is essential: constructor identity does not itself show that the decoder succeeds, the task runs, the reader does not lag, or a particular runtime fixture reaches the branch.

## Reproduction and remaining questions

```sh
python3 research/work-items/RE-017-node115-replay-slot-producer-identity/verify.py --target artifacts/node/115/hl-node
```

Use Capstone 5.0.7 and pyelftools 0.32. Eleven windows retain 1893 instructions and 138 witnesses: eight complete helper FDEs and three instruction-aligned windows in the replay future. The verifier checks FDE membership, exact bytes/transcripts, the installed poll relocation, memcpy binding and four-entry initial-state table. Eleven controls reject an altered artifact or initial-state dispatch, different reader/task owners, a different embedded future, confusing A with the address of its handle, a different decoder-result word, wrong slot stride, missing sequence store, wrong pair offset and ignoring the reader sequence guard.

These are static evidence checks, not target behavioral tests. The exact meaning and ownership of the decoder pair, scheduling, contended/unwind channel behavior, relationship between cursor C and checkpoint height, root provenance and end-to-end replay acceptance remain unclosed. A downstream fixture must supply evidence for those prerequisites rather than treating a shared allocation as proof of the full replay contract.
