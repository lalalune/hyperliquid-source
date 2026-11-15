# RE-008: node115 listener queue — block-list channel send 0x2ceda40, pop 0x2cceb30 and block locate 0x2cd0010

- Component ID: consensus (`docs/COMPONENTS.md`, Consensus; listener root `0x2af8be0` owned by RE-001/RE-012/RE-008 peer-admission work)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `a8616af9432b8d8517b2af677880e117b7c28ef3` (workspace head); no reference-source label was copied
- Claim status: observation (byte-level behaviour of three functions, compared with a model) / inference (the channel is a tokio-style unbounded mpsc list) / unresolved (channel constructor and consumer pairing)
- Scope included and excluded: included are the 64-byte-message `Sender::send` body at `0x2ceda40`, the list `Rx::pop` body at `0x2cceb30` and the block locate/extend helper `0x2cd0010` that send calls directly. Excluded are the channel constructor, the sender/receiver drop paths, the message drop body `0x2c995f0` (stubbed, only its argument is logged), the allocator, and any multi-thread interleaving.

The three functions that carry the listener's only direct producer (`0x2af93b6` inside root `0x2af8be0`) into a queue are now restated as an executable byte-level state machine (semaphore +2 per message with bit 0 = closed and `0xfffffffffffffffe` = overflow abort, tail index xadd, 32-slot 64-byte blocks with ready bitmap, observed-tail release flag at bit 32 and tx-closed flag at bit 33, rx waker state machine, reserved tags `0x8000000000000004/5`), which makes a Rust port of the listener-to-consumer queue possible without guessing the block layout; the 13,538 comparison cases agree with the original machine code on every heap byte, return value and side-effect log, but pairing of this channel with the consumer at `0x2af7c40` is still unproven.

## Reproduce

```
python3 tools/re008_listener_chan_115.py --out research/work-items/RE-008-listener-queue-channel-115
python3 -m unittest tests.test_re008_listener_chan_115
```

The tool refuses any binary whose SHA-256 differs from the target digest, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, decodes instructions from file bytes with a small x86-64 interpreter, and never runs the node. One regeneration takes about 45 s and a few tens of MB. Output files: `cases.tsv` (every fourth of 13,538 cases), `outcomes.tsv` (outcome classes with counts), `functions.tsv` (FDE extents, executed instruction counts and the unexecuted addresses), `controls.tsv` and `equivalent-mutants.tsv` (one-byte code mutants) and `measure.json`.

## Evidence

All addresses are virtual addresses of the #115 image; each function is a whole FDE (`functions.tsv`).

Send `0x2ceda40..0x2cedc4d` (FDE end `0x2cedc4d`), arguments `rdi` = sender `{chan, arc}`, `rsi` = 64-byte message, result in `al`:

```
2ceda4c  mov 0x8(%rdi),%rbx ; 2ceda50 lock incq 0x10(%rbx)      arc counter +1 on every call
2ceda7f  mov 0x1c0(%r14),%rax ; test $1,%al ; jne 2cedb93         bit 0: closed
2ceda98  cmp $-2,%rax ; je 2cedc2e                                 overflow -> abort slot 0x64e02e8
2cedaa2  lea 2(%rax),%rdx ; lock cmpxchg %rdx,0x1c0(%r14)         +2 per message
2cedaef  lock xadd %rbx,0x88(%r14) ; call 2cd0010                  tail index, block locate
2cedb00  and $0x1f,%ebx ; shl $6,%ecx ; movups x4                  slot (index & 31) * 64
2cedb33  lock or %r15,0x810(%rax)                                  ready bit
2cedb3b  0x110(%r14) |= 2 (cmpxchg loop); if old == 0: take 0x100/0x108, xchg 0 -> 0x110, call *0x8(vtable)
2cedbc7  closed path: tag == 0x8000000000000004 -> al = 5 (no drop); else drop copy, lock decq 0x10(%rbx), al = 0
2cedbd6  mov $5,%al                                                success is also 5
```

Pop `0x2cceb30..0x2cced01`, arguments `rdi` = 64-byte out, `rsi` = rx `{head, free, index}`, `rdx` = tx fields (chan+0x80):

```
2cceb4c  and $-32,%rcx ; cmp %rcx,0x800(%rax)         walk head block via +0x808 until start == index & ~31
2ccecdb  next == 0 -> out tag 0x8000000000000005
2ccebb6  bt $0x20 ready ; 0x818 (observed tail) <= index  -> release free block, reset +0x800..0x810,
         re-link behind tx tail with up to 3 cmpxchg on +0x808 (start = tail.start + 0x20), else dealloc slot 0x64df4a0
2ccec90  bt %edx,%esi (32-bit: index mod 32) ; slot copy ; cmp tag with 0x8000000000000003: only tag <= ...03 advances index
2cceccc  not ready: bt $0x21 -> tag 0x8000000000000004 else 0x8000000000000005
```

Locate `0x2cd0010..0x2cd01c2`: same start arithmetic; allocates `0x820` bytes through slot `0x64df480` when `+0x808` is null (start field `+0x20`, overflow check `> 0xffffffffffffffdf` panics through `0x64df520`), and advances the tx tail block by cmpxchg when the block's low 32 ready bits are full and the target block is more than `index & 31` blocks ahead, recording the tail position at `+0x818` and setting bit 32.

Callers (earlier direct-call scan, unchanged): `0x2ceda40` has exactly one direct caller, `0x2af93b6` in `0x2af8be0`. `0x2cceb30` is called from `0x2c8e400`, `0x2c92830`, `0x2cda410` and the poll bodies `0x2cdca20..0x2cddeb0` (sole caller `0x2af7c40`). Nothing here proves that the sender created by the listener's constructor and the receiver stored at `[fut+0x1ab8]` of the state machine `0x2af77f0..0x2af8be0` are one pair.

## Implementation and comparison

`ChannelModel` restates the three bodies on a byte image (`Image2`) with the same absolute addresses; `Rig` runs the original bytes in the shared interpreter (plus `lock xadd`, added for this work) with stubs for the allocator, deallocator, abort/panic slots, the message drop body (argument logged) and two distinct waker vtable entries. Allocation is a bump allocator in both. Each case builds one image, runs both sides on private copies, and compares: return value or panic class, the whole 192 KiB image, and the ordered log of allocations, deallocations, drops and wake calls.

* Random states (6,000): 1–5 linked blocks, bases including `2^64 - 32k`, random ready words with bits 32/33, observed tails, head/free positions, semaphore words (even, odd, `-2`, `-4`), waker states and vtable pointers, tags including both reserved values and their neighbours.
* Sequences (120 channels × 70 steps, 7,538 compared operations): fresh channel driven by send, pop, receiver-close and tx-close; popped tags are also checked against a first-in-first-out queue independent of the model (0 violations).
* Mutants (53 one-byte patches): every conditional jump of the three functions flipped, every 8-bit immediate of group-1/shift/bt instructions incremented; each runs 800 random cases and 40 sequences. 48 are detected. 5 are not and are listed with reasons in `equivalent-mutants.tsv`: they sit on lost-race (cmpxchg failure) branches that cannot fire without a concurrent writer.

## Results and limitations

`measure.json`: cases 13,538 (6,000 random + 7,538 sequence operations), all agree; negative controls 53, detected 48, equivalent 5; FIFO violations 0. Executed instructions: send 103/109, pop 103/106, locate 76/99 (`functions.tsv`). `outcomes.tsv` separates successful sends, closed-channel sends and panicking sends; the finer paths (drops, wake calls, allocations, deallocations, releases) are compared through the side-effect log and the full-image comparison, and are not tabulated separately.

Limits: single-writer semantics only (the 5 equivalent mutants and the 23 unexecuted locate instructions are the lost-race paths); the `rx` struct and the arc/sender wrapper placement are harness choices, only the field offsets inside them are observed; the alloc-failure and unwrap-none panics are modelled but their callees are stubs; the meaning of the 64-byte message is not decoded. Unresolved: the constructor pairing the listener's sender with a consumer, and the dispatch after `0x2af7c45`. No progress gate is requested.

Next question: locate the function that allocates the channel (`0x820`-byte first block plus the `0x1c0`-byte header) and shows which closure receives the sender and which future frame slot receives the rx, then decode the first dispatch arm after `0x2af7c45`.
