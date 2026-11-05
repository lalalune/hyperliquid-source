# RE-001: node115 sibling gate 0x5a52790 two-tag release

- Component: the async environment object shared with the value-transition FDE `0x5a2f550`.
- Target: node #115 Linux x86-64, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`; no inferred source copied or treated as an oracle.
- Question: what exactly does the 126-byte FDE at `0x5a52790` — called by precisely the same ten caller functions as the value transition `0x5a2f550`, and named there as its out-of-scope sibling gate — do with the environment pointer it receives: under what condition does it act, what does it release, and how does the flag byte at `+0x18` choose between the two destructors?
- Status: complete static export of one FDE plus all twelve of its call sites. The two destructor bodies, the shared field-release body at `0x5a52490`, and all wider caller semantics remain unmeasured. No implementation or gate claim.

## Relationship to the sibling packet

`RE-001-async-value-transition-2f550-115` (open PR #3309) pins the
four-state transition `0x5a2f550` end to end and explicitly leaves
this routine out of scope: "sibling gate `0x5a52790` (a separate
routine the same 10 callers also call)". This packet answers that
one leftover question and nothing else. The pairing is not just
prose: the census in `records.json` recomputes the direct call
sites of both routines from the target and proves the caller-FDE
set of the gate equals the caller-FDE set of the transition
(exactly the ten FDEs listed under Callers). Three merged packets
(`RE-001-node115-consensus-override-descent`,
`RE-001-node115-gossip-peer-status-report`,
`RE-001-node115-home-node-disable-gates`) cite `0x5a52790` only as
a `direct_target` inside their own records; none of them pins its
meaning, and no merged README mentions it.

## Scope and binding

`0x5a52790..0x5a5280e` is the complete measured FDE, **126 bytes /
38 instructions**. `records.json` preserves raw bytes, body hash,
file mapping, the FDE record, every call/branch edge, the three
slot resolutions, the panic-string binding, the resume binding,
and the full census. `native.asm` retains the full GNU
disassembly of the FDE; `callers_excerpt.asm` retains one caller
window per call site. There is no byte normalization. An FDE
describes an unwind range, not a guarantee that all semantics or
cold parts are closed.

The incoming convention is one argument, an environment pointer
in `rdi`. The routine produces no value: its normal exit is a
plain `ret`, its acting exit is a tail jump, so any result
register is meaningless on both paths. No source-level name for
the environment object or its fields is recovered; offsets are
the claim.

## Ordered behaviour

1. **First tag gate.** The byte at `env + 0x90` is compared
   against 3 (`cmp byte ptr [rdi + 0x90], 3` at `0x5a52794`). On
   inequality the routine restores its two saved registers and
   returns at `0x5a527ce`, having read nothing else and written
   nothing.
2. **Second tag gate.** The byte at `env + 0x88` is compared
   against 3 (`0x5a5279d`). On inequality, the same immediate
   return. Only when **both** tag bytes equal 3 does the routine
   act. (The checks run in the order `+0x90`, then `+0x88`.)
3. **Counter release setup.** `r14` keeps the environment
   pointer; `rdi` becomes `env + 0x20`, the address of a counter
   field. The flag byte at `env + 0x18` selects the path:
   - **Flag nonzero** (`0x5a527b6`): `rax` = the counter pointer
     stored at `env + 0x20`; `lock dec qword ptr [rax]`
     atomically decrements the pointed-to counter. If the
     decrement leaves it nonzero (`jne 0x5a527de`), nothing
     further happens to the counter. If it reaches zero, the
     routine calls through slot `0x64dfdc8` — RELATIVE relocation
     resolving to `0x5ce8da0` — with `rdi` still `env + 0x20`,
     i.e. the destructor receives the address of the counter
     field, not the counter pointer.
   - **Flag zero** (`0x5a527cf`): the identical load, locked
     decrement and zero test, but the zero case calls through
     slot `0x64dfdb8`, resolving to `0x5ce86d0`, with the same
     `rdi = env + 0x20`.
   The flag therefore selects *which destructor runs when the
   last reference drops*, and nothing else; the decrement and
   the zero test are shared verbatim.
4. **Field release (tail).** Both paths join at `0x5a527de`:
   `rdi = env + 0x28`, the frame is torn down, and the routine
   tail-jumps to `0x5a52490` (`jmp 0x5a52490` at `0x5a527ec`).
   That target is the same field-release routine the sibling
   transition's false path calls for the `+0x28` field; its body
   is **not** measured here, only the shared address and the
   argument.
5. **Cleanup pad.** At `0x5a527f1`, reached only while unwinding
   out of one of the two destructor calls: the in-flight value
   in `rax` is saved to `rbx`, `0x5a52490` is *called* (not
   tail-jumped) with `rdi = env + 0x28`, and then the pad calls
   the `_Unwind_Resume` PLT stub at `0x63f0a50` (slot
   `0x64ee178`, JUMP_SLOT relocation naming `_Unwind_Resume`)
   with `rdi = rbx`. So even on the exceptional path the
   `+0x28` field release runs exactly once.
6. **Final guard call.** The FDE's last instruction
   (`0x5a52808`) calls through slot `0x64df4c0`, resolving to the
   20-byte shim at `0x1680cab`, which loads the 36-byte string
   `panic in a destructor during cleanup` (at `0x46e9bd`) and
   calls the panic runtime. It is reachable only if
   `_Unwind_Resume` were to return, which it does not; it is the
   standard non-returning continuation guard, and the two
   `int3` bytes after the FDE (`0x5a5280e`) are inter-function
   padding, not part of the routine.

`rbx` is saved and restored but never written on the normal
paths; it exists for the cleanup pad's use in step 5. The
routine reads no other environment bytes and writes nothing
except through the locked decrement: the only memory it mutates
directly is the counter word behind the pointer at `env + 0x20`.

## Transfers

Leaving the routine: two indirect calls (the destructor pair,
step 3), one direct tail jump and one direct call to
`0x5a52490` (steps 4–5), one direct call to the `_Unwind_Resume`
PLT stub (step 5), and one indirect call to the cleanup-panic
shim (step 6). Every internal branch (`jne`/`je`/`jmp`) lands
inside the FDE. `records.json` lists all twelve call/branch
edges with their raw bytes.

## Callers

The census finds **exactly twelve direct call sites in ten
caller FDEs**, no direct tail jumps, no stored qword holding
the routine's address anywhere in the binary, and no RELATIVE
relocation addend equal to it — the routine is reachable only
through these calls:

- `0x5a5ed9c` and `0x5a607f4`, inside `0x5a5e290..0x5a60a43`,
  `rdi = r12`;
- `0x5a61e92`, inside `0x5a61e40..0x5a6221b`, `rdi = r15`;
- `0x5a68b74`, inside `0x5a64aa0..0x5a69c05`, `rdi = r14`;
- `0x5a6b0e6`, inside `0x5a6a640..0x5a6bfaa`, `rdi = r15`;
- `0x5a6d236`, inside `0x5a6d200..0x5a6d385`, `rdi = r15`;
- `0x5a71144`, inside `0x5a71040..0x5a7172a`, `rdi = r15`;
- `0x5a794de`, inside `0x5a794a0..0x5a79722`, `rdi = r15`;
- `0x5a7e5ff`, inside `0x5a7e540..0x5a7f395`, `rdi = r15`;
- `0x5a85065` and `0x5a89353`, inside `0x5a82670..0x5a89535`,
  `rdi = r15`;
- `0x5a8a15b`, inside `0x5a897e0..0x5a8a1cc`, `rdi = r13`.

Every site sits in a caller cleanup block: the immediately
preceding instructions stash the in-flight `rax` value into
another callee-saved register (or onto the stack) and move the
environment pointer — held in a callee-saved register of that
caller — into `rdi`. `callers_excerpt.asm` retains each window
verbatim. At the two callers checked instruction-by-instruction
against the sibling packet (`0x5a6d200..0x5a6d385` and
`0x5a794a0..0x5a79722`), that register holds `caller_rbx + 0x80`
resp. `caller_rbx + 0x10` — exactly the environment pointer the
same FDE passes to the transition `0x5a2f550`, which is why the
gate's `+0x88`/`+0x90` tag bytes are the transition object's own
fields. Corroborating this, the `0x5a6d200` caller, after its
transition call returns false, re-tests the same two bytes
itself (`env + 0x90` at caller `+0x110`, `env + 0x88` at caller
`+0x108`, in the gate's order) and then performs the gate's own
release inline: `rdi = env + 0x20` (caller `+0xa0`), the same
flag byte (caller `+0x98` = `env + 0x18`), the same locked
decrement.
Wider caller semantics beyond the sites, the FDE ranges, the
pinned `rdi` moves and these two spot checks are not claimed.

## NOT claimed

What the environment object, its two tag bytes, the counter, or
the `+0x28` field denote; what either destructor (`0x5ce86d0`,
389 bytes; `0x5ce8da0`, 801 bytes) does with the field address it
receives; what the shared release at `0x5a52490` (136 bytes)
does — its body contains the same flag-selected locked-decrement
idiom over its own sub-fields, noted as an observation only; how
the LSDA assigns the cleanup pad to the two destructor calls
(the pad's position and contents are pinned, the assignment is
the only reading the layout admits but is not decoded from the
LSDA); and behaviour on a dangling environment or counter
pointer (the binary dereferences both unconditionally once the
tags pass; no model is offered).

## Reproduction and controls

Run from the repository root with Python **3.12.3**, Capstone
**5.0.7**, GNU objdump **2.42**:

```sh
python3 tools/async_gate_release_52790_115.py --write
python3 tools/async_gate_release_52790_115.py
python3 -m unittest discover -s tests -p test_async_gate_release_52790_115.py -v
```

The first command regenerates the static packet, the second
checks exact replay. The objdump exports are produced from the
repository root with the target as the relative path
`artifacts/node/115/hl-node`, so no checkout-specific absolute
path enters the artifacts. The node is read only; no captured
executable, emulator, socket, chain or signing operation runs.
All **17 tests** pass. Twelve decoded-instruction corruption
controls cover both tag offsets, the first tag's value, the
counter-field and flag offsets, the flag's branch direction,
the locked decrement itself, the nonzero-skip branch, the
flag-nonzero call slot, the tail field offset, the tail target,
and the pad's release call. Wrong-artifact and
truncated-decode controls also reject. The census assertions
(twelve sites, ten FDEs, empty tail-jump/stored/addend sets,
caller-set equality with the sibling) run against the target on
every invocation. These are structural checks of the authentic
target evidence, not execution of the target or a differential
source implementation.

## Results and limitations

One bounded question is answered completely at the
static-evidence level: the gate is a two-tag precondition
(both bytes equal to 3) on a flag-selected, reference-counted
release of the `+0x20` counter field, followed in all cases by
the shared release of the `+0x28` field — the teardown
counterpart the transition's ten callers run from their cleanup
blocks. Not measured: the destructor bodies, the `0x5a52490`
body, the LSDA, and any source-level names. No progress gate is
requested. Repository-wide gates (`make verify`, `make test`)
are not claimed: their baseline fails on unmaterialized LFS
objects belonging to older packets, unrelated to this one; the
packet's own tool, tests and `make catalogue-check` pass.
Next question: what do the two destructors at `0x5ce86d0` and
`0x5ce8da0` do with the counter-field address, and why does the
flag byte at `+0x18` need two of them?
