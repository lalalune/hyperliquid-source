# RE-001: node #115 chain resolve-and-dispatch 0x5d52d70

Task RE-001. Bounded question: what does the whole 177-byte
routine at `0x5d52d70` (FDE `0x5d52d70..0x5d52e21`) do with its
single owner argument, end to end, and which handler does it
tail-dispatch to?

## Answer, pinned to the target binary

The routine takes one argument, an owner pointer in `rdi`, and
never returns normally: it always ends in a tail jump to a
handler resolved from a chain. In order:

1. **Acquire.** Call `0x60d5390` with owner `+0x700`. That
   callee is a no-op stub (`endbr64; ret`, FDE
   `0x60d5390..0x60d5395`, shipped whole as `acquire.txt`), so
   the call returns at once and changes nothing observable.
2. **Counter.** The dword at owner `+0x1444` is incremented by
   1 (`addl $0x1,0x1444(%rbx)` at `0x5d52d8b`).
3. **Head.** The node pointer at owner `+0x318` is read (node
   N0). Each node contributes a handler value
   H = `*( *(node) + 0x170 )`, and the next node is
   `*(node + 0x48)`.
4. **Resolve.** Each handler is compared against the previous
   one, starting from the previous value held in the global at
   `0x64ed590`:
   - if H0 differs from the global, dispatch H0 with node N0;
   - else if H1 differs from H0, dispatch H1 with node N1;
   - else if H2 differs from H1, dispatch H2 with node N2;
   - else if H3 differs from H2, dispatch H3 with node N3;
   - else dispatch H4 with node N4, unconditionally.
   The comparisons are AT&T `cmp` + `jne`: `cmp mem,%rax`
   computes rax minus the global, `cmp %rax,%r10` computes
   r10 minus rax, and so on, so `jne` fires exactly on
   inequality in each pair. The dispatch therefore goes to the
   first handler that changes along the chain, or to H4 when
   the first four handlers all match their predecessors.
5. **Dispatch.** Tail jump (`jmp *%rax` at `0x5d52e02` or
   `jmp *%r10` at `0x5d52e1e`) to the resolved handler with
   (`rdi` = node, `rsi` = `0x5dd6060`, `rdx` = owner,
   `rcx` = 2, `r8` = 0, `r9` = 0). Because it is a tail jump,
   the handler returns directly to this routine's caller.

## The relocated global

The file bytes at `0x64ed590` are 0, but that is only the
pre-relocation image: the binary carries an
`R_X86_64_RELATIVE` relocation at `0x64ed590` with addend
`0x5d4b320` (see `relocations.txt`), so the loaded value is
`0x5d4b320`. The model pins that relocated value. The routine
at `0x5d4b320` itself (FDE `0x5d4b320..0x5d4b3e2`, shipped
whole as `sentinel.txt`) starts by walking the same `+0x48`
chain and comparing its own handler against the same global,
which corroborates that the global holds a chain-handler
value; its wider behavior is not modelled. The address passed
in `rsi`, `0x5dd6060`, is executable code (FDE
`0x5dd6060..0x5dd6097`, shipped whole as `rsi_target.txt`);
its body is not modelled, only its address.

## Transfers

The routine's own control transfers are exactly one direct
call (the acquire stub at `0x5d52d7f`), no direct tail jump
out, no indirect call, and two indirect tail jumps (the two
dispatch sites). Its internal direct jumps (`jne` at
`0x5d52da3`, `0x5d52db6`, `0x5d52dc9`, `0x5d52ddc`) all land
inside the routine. It has no landing-pad block; the byte at
`0x5d52e21` is `int3`, and the block from `0x5d52e22` is a
separate FDE (`0x5d52e22..0x5d52e56`), not part of this
routine.

## Consumers (site-only)

The census finds exactly six direct call sites, no tail
jumps, no stored qwords, and no RELATIVE addend for the
routine address itself:

- `0x5d5ff71`, inside caller `0x5d5fec0..0x5d6008a` (its
  `rdi` setup lies outside the excerpt window and is not
  pinned);
- `0x5d60480`, inside caller `0x5d603b0..0x5d60525`, which
  moves its `rbx` into `rdi` before the call;
- `0x5d7501f`, inside caller `0x5d74aa0..0x5d764c8`, which
  moves a caller stack value at `0x8(%rsp)` into `rdi`
  before the call;
- `0x5d915f1`, inside caller `0x5d914f0..0x5d916d9`, which
  moves its `r14` into `rdi` before the call;
- `0x5e5625b`, inside caller `0x5e54860..0x5e56f2e`, which
  moves its `rbx` into `rdi` before the call;
- `0x5edc11d`, inside caller `0x5edbac0..0x5edc3b3`, which
  moves its `rbp` into `rdi` before the call.

Only the sites, FDE ranges, and the pinned moves above are
claimed; wider caller semantics are not.

## NOT claimed

What the owner, the nodes, or the handlers denote; what any
dispatched handler does; what the routines at `0x5d4b320`
and `0x5dd6060` do beyond the pinned first instructions and
addresses noted above; caller semantics beyond the sites, FDE
ranges, and pinned moves; or behaviour on dangling pointers,
a null owner or node (the model raises), a chain that ends
before a dispatch (the model raises), or a resolved handler
of 0 (the binary would tail-jump to address 0; the model
raises instead, stated openly). A runtime write to the global
at `0x64ed590` after load would change the first comparison;
only its relocated value is pinned. The model folds the
double indirection `*( *(node) + 0x170 )` into the node's
handler value; the walk order and the comparisons are exactly
the binary's.

## Verification

Tool versions: GNU objdump/readelf (Binutils 2.42), Python
3.12.3. Reproduce from the repository root:

    python3 research/work-items/RE-001-chain-dispatch-52d70-115/export_excerpts.py
    python3 research/work-items/RE-001-chain-dispatch-52d70-115/census.py
    python3 research/work-items/RE-001-chain-dispatch-52d70-115/verify.py
    python3 tests/test_chain_dispatch_52d70_115.py

`verify.py` reports ALL CHECKS PASSED (digest, provenance,
manifest, excerpt regeneration byte-for-byte from a fresh
objdump run, every excerpt instruction byte-for-byte against
the raw binary, FDE ranges, the relocation record, census
including the per-site caller-function check against the
smallest enclosing FDE, records, model tests). Three extra
spot instructions were also checked byte-for-byte against a
fresh objdump run and the raw binary (`0x5d52d8b`,
`0x5d52dac`, `0x5d52de5`) beyond `verify.py`'s own spots.
Model `tools/chain_dispatch_52d70_115.py` with
`tests/test_chain_dispatch_52d70_115.py` (30 checks pass:
each dispatch step, the unconditional fifth step, the exact
dispatch argument list, the counter increment, a custom
previous value, input guards). Repository-wide gates
(`make verify`, `make test`, `make catalogue-check`) are not
claimed: their baseline is affected by missing LFS material
and by the absence of cargo/rustc on this machine.

## Concrete next step

What the dispatched handlers do once they receive
(node, `0x5dd6060`, owner, 2, 0, 0), and what the six callers
do with the return that comes back through the tail jump.
