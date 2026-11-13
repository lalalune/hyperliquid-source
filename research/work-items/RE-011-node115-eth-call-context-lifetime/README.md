# eth_call execution context lifetime

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. This is a bounded static advance of HL115-095. No captured code was executed or emulated.

The existing eth_call route reaches executor `0x2962aa0` with an opaque context. The selected adapter constructs one local object, supplies that same stack address to preparation and execution, then destroys it after the executor returns. A cleanup landing path also destroys the same object. The destructor walks two separately stored hash-table-shaped containers, releases referenced objects and their allocations, and processes another owned sequence. This closes selected local-object lifetime, not global state isolation.

## Prior boundary and actual lineage

[#2114](https://github.com/lalalune/hyperliquid-source/pull/2114), `RE-011-eth-call-path-115`, already establishes the eth_call worker, adapter `0x2a098b0`, normalized input and executor handoff; it explicitly leaves overlay disposal and persistent effects unresolved. Its routing and interpretation are reused. The new observation is the identity of the context argument from its constructor through the selected normal continuation and cleanup, together with actual destructor structure.

At `0x2a098f4`, the adapter passes `rsp+0x378` to slot `0x64e6f58`, whose relative relocation identifies constructor `0x5be62f0`. The constructor writes fields covering object offsets `+0x00` through `+0x8f` before returning. The stack allocation has a stable frame base on the selected path. The same `rsp+0x378` is passed as the third argument to `0x2a2ffe0` at `0x2a0a359`, fourth argument to `0x2a04660` at `0x2a0a3a9`, second argument to `0x2a2fd10` at `0x2a0a5cc`, and third argument to `0x2962aa0` at `0x2a0aa67`. Their internal behavior is not reconstructed here.

On normal executor return, `0x2a0aa6c` jumps to `0x2a0a905`; an Arc-like reference at stack `+0xcc8` is decremented, with the slow-drop helper on the zero branch. The adapter then passes `rsp+0x378` to `0x29f4eb0` at `0x2a0a92d` and returns. Another cleanup landing path supplies that same address to `0x29f4eb0` at `0x2a0ac72`. This does not establish that every unwind site reaches that landing path.

## Destructor observations

`0x29f4eb0` first tests object `+0x20`, and when nonzero scans control bytes addressed from `+0x18` using an occupied-entry count from `+0x30`. Per-entry references are decremented, with slot `0x64e4fa8` called on zero; nonempty per-entry allocations and then the container allocation pass to the deallocator at slot `0x64df4a0`. The second container similarly uses object `+0x48`, control pointer `+0x40`, and occupied count `+0x58`, decrementing entry references before freeing its allocation. The remainder starts from pointer `+0x08` and count `+0x10`, then processes its elements and corresponding allocation; a further allocation is addressed via `+0x68/+0x70`. These descriptions are conditional on valid object invariants and ordinary returns of cleanup helpers. Field semantics and the full destructor's exceptional paths are not inferred from layout alone.

Destroying this local object does **not** prove that the executor made no shared, external or durable writes, or that its result was not committed or copied elsewhere. The helpers retain their own effects and aliases as open boundaries. Full eth_call semantics, backend ownership, all error routes, and the backlog's isolation guarantee remain open; no progress gate is advanced.

## Validation

The verifier binds 11 instruction windows, 1,006 bytes / 251 instructions, 55 facts and 52 changed-byte controls to the full original digest. The facts include actual stack offsets, call targets, constructor stores, destructor field accesses and relocation targets. Controls reject selected evidence drift; pointer identity and cleanup interpretation require the stated static dataflow reasoning. No synthetic callback or target execution is substituted for the executor.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-011-node115-eth-call-context-lifetime/verify.py --target /path/to/original/hl-node
```
