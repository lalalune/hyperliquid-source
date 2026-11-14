# eth_call task permit ownership after acquisition

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. Bounded static advance of HL115-098 / RE-011. The captured program was never executed or emulated.

The previously established route ends at an indirect poll, leaving the acquired permit's owner and release timing unclear. This packet connects that actual task allocation to its result reader, worker, and unstarted-body destructor. The successful gate's three-word descriptor becomes part of the worker closure. On normal return from the expensive-work helper, the worker releases its count before copying the result toward publication. Polling the join result uses a different vtable entry and does not execute that work directly.

## Reused evidence and remaining scope

- [#2080](https://github.com/lalalune/hyperliquid-source/pull/2080), `RE-011-evm-permit-routing-115`, establishes selector-0 acquisition and the `0x2e4ac30` indirect post-acquisition poll boundary.
- [#2114](https://github.com/lalalune/hyperliquid-source/pull/2114), `RE-011-eth-call-path-115`, establishes the registered eth_call route, `0x6449ab0` task vtable, worker `0x2b215d0`, and its call to `0x29c1ee0`. Their identification is reused, not a new finding.
- [#2417](https://github.com/lalalune/hyperliquid-source/pull/2417), `RE-014-permit-followup-115`, establishes conditional empty-waiter restoration in `0x5ce5310`. This packet binds the actual owner/count passed to that boundary; it does not reproduce or generalize that helper's internals.

The new result is the descriptor lineage through the allocation and closure take, the distinct join-reader dispatch, the normal worker release ordering, and the stage-0 nonempty-body cleanup path. Complete cancellation interleavings, scheduler behavior, registration-map survival, error-to-wire conversion and the full HL115-098 acceptance criteria remain open. No completion gate is advanced.

## One descriptor across the actual task

`0x2a2a0e0` binds the literal `eth_call`, length 8, at `0x2a2a1fd`/`0x2a2a20b`. Its gate call is `0x2a04070` at `0x2a2a2dd`. For returned raw tag `0x28`, the three words loaded from result `+8/+16/+24` are saved and then copied to owner `+0x658/+0x660/+0x668`. The closure base is owner `+0x430`, so this descriptor is closure `+0x228` and the adjacent worker Arc is closure `+0x220`. This derivation does not assign semantics to the descriptor's otherwise unexamined third word.

The handler copies the full `0x240`-byte closure to the input of `0x2b3c190`. That factory copies it to stack `+0x404`; its body copy moves `0x24c` bytes from stack `+0x3f8` to `+0xc4`. The header starts at `+0x80`, making the closure's final task-relative offset `0x50`. The descriptor is therefore at task `+0x278`, with its count dword at `+0x280`. A complete `0x300`-byte task allocation is copied and passed to the scheduler; the returned allocation pointer is saved at handler owner `+0x690`.

| Boundary | Actual location / target |
| --- | --- |
| Successful gate descriptor | result `+8`, then closure `+0x228` |
| Installed task vtable | task `+0x10` points to `0x6449ab0` |
| Worker executor entry | vtable `+0x00` relocates to `0x2b215d0` |
| Join result-reader entry | vtable `+0x18` relocates to `0x2b14fd0` |
| Join-interest drop entry | vtable `+0x20` relocates to `0x2b1a8a0`; internals not reconstructed here |
| Task body / closure | task `+0x40` / task `+0x50` |
| Acquired descriptor in task | task `+0x278`, count dword `+0x280` |

`0x2e4ac30` receives the address of owner `+0x690`, loads the task, loads its vtable, and calls vtable `+0x18`. The concrete target `0x2b14fd0` asks the readiness helper `0x5cdb250` about task `+0x290`. A not-ready result takes its epilogue without touching the closure. The ready path consumes stage 1 to stage 2 and copies the `0xa0`-byte result. The readiness helper and cooperative-budget paths are retained as dependencies, not reconstructed scheduler semantics.

## Worker return and unstarted cleanup

In the selected runnable, stage-0 worker path, `0x2b215d0` takes the closure's first two words and replaces them in the task with `(2, 0)`, the exact empty sentinel at `0x452990`. It copies the remaining `0x230` bytes and reassembles the closure at stack `+0x650`. Its descriptor is now stack `+0x878`; that pointer survives in R14 across the actual `0x29c1ee0` call at `0x2b21812`.

After this call returns normally, the worker reloads the descriptor, zero-extends its dword count, and, for a nonzero count, acquires the byte lock at acquired-owner `+0x10` and calls `0x5ce5310` with that owner/lock and that exact count. A zero count bypasses restoration. Both paths decrement the acquired owner's Arc reference. These operations precede the result copy at `0x2b218b4` and the separate worker-Arc release. Thus normal expensive-work return is the release point on this path; it is not postponed until the client next polls the completed result. This is an ordering claim under normal returns of the intervening helpers, not a claim that the worker always returns or that every waiter receives a permit.

The actual full-task destructor `0x2a98dc0` passes task `+0x40` to `0x2a97740`. For body stage 0, this checks the same two-word empty sentinel. A nonempty closure is passed at body `+0x10` to `0x2a93550`; its descriptor at closure `+0x228` and count at `+0x230` drive the same nonzero-count restoration boundary, followed by Arc decrement. An already-taken `(2, 0)` closure skips that destructor path. This proves cleanup when this unstarted-body destructor is reached. It does not establish when arbitrary request cancellation reaches it, or all unwind paths through the scheduler and work helper.

## Validation and use

The packet binds 9 windows, 5,535 bytes / 1,184 instructions, 106 facts and 94 changed-byte controls to the entire original artifact digest. Controls cover descriptor offsets, copy sizes, vtable slots, count loads, ownership sentinels and the work/release call targets. They reject drift in the evidence; manual dataflow reasoning supplies the ownership interpretation. No callback model, inferred scheduler implementation, or source-level permit simulation is substituted for the native lineage.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-011-node115-eth-call-permit-lifetime/verify.py --target /path/to/original/hl-node
```

A future source-owned RPC executor can use this contract to place the acquired descriptor in the spawned closure and release it on normal work completion. Before claiming full equivalence, it must additionally close pending cancellation, work-helper unwind, scheduling/interest state transitions, registration-map lifetime and wire errors.
