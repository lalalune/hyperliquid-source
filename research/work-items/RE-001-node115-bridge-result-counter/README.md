# RE-001: map node115 bridge result gate and checked counter subtraction

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static research; no inferred source was copied.

- Complete FDE `[0x44d83f0,0x44d8583)`: 403 bytes /77 instructions.
- Complete FDE `[0x2c3edb0,0x2c3f38a)`: 1498 bytes /312 instructions.

Export denominator: **1901 bytes /389 instructions**.
These are evidence extents, not recovered or compiled-comparison coverage.

## Question and local convention

When does the bridge-associated wrapper subtract from its aggregate-like word,
and does the call occur before or after that store? The bounded result-gate and
counter ordering are recovered; no transfer, withdrawal, balance unit or durable
state transition is claimed.

The first argument is retained as object RBX and incoming RCX as amount-like
R14. Two incoming pointers each supply20 copied bytes. The incoming R8 word
and other copied fields form arguments to0x3689150, with object+0x80. The
helper's map mutation, ownership and result type are unclosed.

## Result gate and subtraction

The helper writes a local result at stack+0xb0. The word comparison at
`0x44d8448` continues only on raw tag **0x1a2**. Other tags copy112 local bytes
into diagnostic arguments, call through0x64df6a0 and reach UD2 if it returns.
There is no normal local counter-store path from that branch.

On0x1a2, the wrapper loads object+0x1c8 and subtracts the saved incoming RCX
as unsigned64 arithmetic. JB at `0x44d845e` selects the borrow path BEFORE
`0x44d8464` stores the result back to+0x1c8. Thus equality writes0, and a
larger subtrahend does not locally wrap and store. The helper call has already
occurred before this arithmetic guard, so transactional rollback or absence of
prior side effects is not established.

The borrow path calls an assertion-shaped slot at `0x44d8524`; its complete
nonreturn/unwind behavior is unknown. If it returns, control falls into the
tracing setup at0x44d852a WITHOUT a counter store and without rechecking the
normal tracing flag. On the ordinary stored path, the global flag0x64f01d8
gates that same tracing setup. No trace helper's behavior is assigned here.

## Actual caller and source binding

At `0x2c3f2c6`, the actual indirect call slot resolves to0x44d83f0. It passes
an object at a saved pointer+0xba0, an identity pointer in RSI, another local
20-byte record in RDX, a local word in RCX, and RBX in R8. An earlier result in
that caller is independently tested against0x1a2 before this wrapper is invoked.
After the wrapper, additional helpers and stores run; their business semantics,
rollback and event closure are not claimed. This is one caller, not a census.

The complete wrapper's actual Location LEA at0x44d84f8 binds the retained
`l1/src/bridge2.rs:145:95` metadata. A diagnostic association is not recovery of
an original function or result-enum name. Valid native inputs and ordinary
helper ABI preservation remain preconditions.

## Reproduction and negative controls

Linux Python3.12.3 and GNU binutils2.42; no target execution or emulation:

```sh
python3 research/work-items/RE-001-node115-bridge-result-counter/collect.py --output work/bridge-replay --check
python3 -m unittest discover -s tests -p test_four_bridge_static.py -v
```

The collector authenticates the complete target before any native command or
output, uses a private non-executable copy, agrees on complete unwind ranges
and relocation records with independent readelf, and verifies contiguous native
instruction bytes. Full original bodies, raw FDE/CIE, LSDA coordinates, every
measured direct/RIP call and source Location binding are retained. Text exports
trim trailing whitespace only after instruction-byte validation.

5 focused tests cover original anchors, exact export regeneration, wrong
artifact identity rejection before output, independent corruption of all claim
anchor groups and mutations of actual semantic sites. The dedicated sites
change the raw tag/condition, field displacement, arithmetic or callback/result
branch relevant to this question. Changes occur only in private Python arrays;
neither original nor altered instructions are executed or emulated.

All component gates remain false. No root Cargo graph, source-built node, binary
equivalence, complete original Rust types, protocol execution, signing, chain
action, paid dataset or live user fixture is introduced. New code/analysis is
root MIT; imported artifacts retain their existing terms. Full repository checks
and generated inventory integration are recorded with the final submitted head.
