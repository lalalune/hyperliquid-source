# RE-001: what the node #115 lu.rs conversion's passed-through context pointer points to — and what the coop-path call does with it

- Component: `base/src/lu.rs` conversion context pointer, answered through the
  coop-path callee at `0x5cf3b90` and its proceed function at `0x5cfc310`.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only migration).
- Question: packet #184 (PR #2125, open) left open what the conversion's
  passed-through context pointer points to, and what the `0x5cf3b90` coop-path
  call does with it. Answer, in one paragraph: the context pointer `P` points
  to a pointer `Q`, and `Q` is a (function table, payload) pair. The coop
  callee either tail-calls the table's slot 2 with the payload, or hands
  `(cell+0x20, Q)` to a dedup-caching proceed function that calls the table's
  slot 0 with the payload unless the last cached pair already equals
  `(Q[0], Q[1])`. The choice between those two exits is driven by a Tokio
  thread-local coop budget cell. This packet cites #183 (PR #2106) and #184
  (PR #2125) as the inviting prior packets; #183's conversion body and #184's
  helper body are cited, not re-claimed. The new bytes claimed here are the
  coop callee and the proceed function only.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| coop callee (characterized) | `0x5cf3b90..0x5cf3c32` | 162 | 44 |
| proceed function (characterized) | `0x5cfc310..0x5cfc3d3` | 195 | 58 (47 main + 11 landing pad) |

The coop FDE is at `.eh_frame` section offset `0x33fef8` (length `0x34`,
CIE `0x00000000`). The proceed FDE is at `.eh_frame` offset `0x72ed08`
(length `0x3c`, CIE `0x39672c`); its main body returns at `0x5cfc3a5` and
its landing-pad block runs `0x5cfc3a6..0x5cfc3d3`. All bodies are hash-pinned
without normalization. Coordinates are ELF virtual addresses (PIE);
`.text` file offset = VA − 0x1000, `.data.rel.ro`/`.got` file offset =
VA − 0x2000, `.rodata` file offset = VA.

## The dereference chain (the structural answer)

The conversion's second argument is passed through untouched at every hop,
verified instruction by instruction:

| Hop | Instruction | Site |
| --- | --- | --- |
| conversion entry saves it | `mov r15, rsi` | `0x15d5cc1` |
| conversion passes it to the helper | `mov rsi, r15` | `0x15d5f3e` |
| state-machine entry saves it | `mov r14, rsi` | `0x15d6e05` |
| state machine passes it to the conversion | `mov rsi, r14` | `0x15d6e49` (call `0x15d6e4c`) |
| caller-2 entry saves it | `mov r14, rsi` | `0x15d5b0b` |
| caller-2 passes it to the conversion | `mov rsi, r14` | `0x15d5bc4` (call `0x15d5bc7`) |
| helper entry dereferences it once | `mov rsi, [rsi]` | `0x5cf2d41` |
| helper passes the dereferenced value on | `mov rdi, rsi` | `0x5cf2ef4` (call `0x5cf2efe`) |

So: context pointer `P` → `[P] = Q` → `Q[0]` = function table,
`Q[1]` = payload. The coop callee uses `Q` two ways: its tail path loads
`rax = [Q]` and `rdi = [Q+8]` and jumps to `[rax+0x10]` (table slot 2 with
the payload), while the proceed path calls `[rax]` — the function pointer
stored at `Q[0]` itself (table slot 0) — with the payload in `rdi`.
`Q[0]` is therefore a table with callable slots at `+0x0` and `+0x10`.
The Rust type identity of `P`/`Q` is **not** asserted: no source in tree,
and the table's slot `+0x8` is never called on any observed path.

## The coop callee: TLS state, budget cell, two exits

`0x5cf3b90` takes `(rdi = Q, rsi = Location)`. Its second argument — the
`tokio/src/task/coop/mod.rs:397:13` Location the helper passes — is never
read anywhere in the body (it is overwritten at `0x5cf3bb6` and `0x5cf3c02`
before any use). The body proper:

- TLS base `rbx = -0x130`. State byte `fs:[-0xe8]`: `1` skips init and goes
  to the budget check; `2` jumps straight to the tail path; any other value
  runs TLS init (`rdi` = TLS base, `rsi` = `0x5cdf410`, call through GOT
  `0x64e0510` → `0x5ca0d20`, the same init slot the helper uses), then sets
  `fs:[-0xe8] = 1` and falls through.
- `fs:[-0xea] == 2` → tail path.
- Budget cell `rax = QWORD fs:[-0x108]`: null → tail path.
- `[cell] != 1` → proceed path. `[cell] == 1`: if `[cell+0x10] >=
  i64::MAX`, the panic path (`lea rdi, [0x64c6380]`, the
  `multi_thread/worker.rs:922:22` Location, call through GOT `0x64e1090` →
  `0x1680ba0`, then `int3`); if `[cell+0x18] == 0` → tail path; otherwise
  proceed path.
- Proceed path: `rax = cell + 0x20`, `rsi = Q`, `rdi = rax`, tail-jump to
  `0x5cfc310`.
- Tail path (`0x5cf3c14`): `rax = [Q]`, `rdi = [Q+8]`, `jmp [rax+0x10]`.

Why the helper reaches the coop call at all (from #184's helper body,
re-read here): the helper takes the coop path exactly when the TLS word
`fs:[-0xec]` has low bit `1` and its second byte `fs:[-0xeb]` is `0`
(branch `0x5cf2d99 je 0x5cf2ef4`). After the coop call returns, the helper
sets `al = 1` and returns true — so the coop path always yields tag 3
(set state) in the conversion, whatever the coop callee did internally.

## The proceed function: a consecutive-pair dedup cache

`0x5cfc310` takes `(rdi = cell+0x20, rsi = Q)`. The struct at `cell+0x20`
is a Vec-like: `[0]` = guard/counter (see below), `[8]` = capacity,
`[0x10]` = buffer, `[0x18]` = length; entries are 16-byte pairs.

- Guard: `[rdi]` must be `0` on entry. The body sets it to `-1`, and both
  normal exits leave it `0` again (the dedup-hit path stores the zeroed
  `rax`; the call path loads `-1`, increments, stores `0`). A nonzero entry
  diverts to the `0x5cfc3a6` block, which ends in `_Unwind_Resume` and never
  returns normally (see open points).
- If length is nonzero, the last entry is compared against `(Q[0], Q[1])`
  (`cmp [rdx+rcx-0x10], rax` and `cmp [rdx+rcx-0x8], rdi`, 16-byte stride).
  Equal → skip the call, leave the guard `0`, return.
- Otherwise call `[rax]` (table slot 0) with `rdi = Q[1]`. The returned
  `(rax, rdx)` pair is stored as the new last entry, length is incremented,
  and the buffer grows through GOT `0x64ecc20` → `0x5ce7020` when
  length == capacity. The guard is restored to `0` and the function returns.
- The landing-pad block (`0x5cfc3a6..0x5cfc3d3`) cites
  `tokio/src/runtime/scheduler/defer.rs:16:42` and ends in `_Unwind_Resume`.

## Sharing: this is Tokio machinery, not lu-specific

- The coop callee has **52 indirect call sites through GOT slot
  `0x64e0520`** (45 FDEs; every site confirmed by per-FDE objdump as
  `call qword ptr [rip+disp]` resolving to that slot, including the helper's
  site `0x5cf2efe`) and **0 direct `E8` callers**. Its only relocated-data
  reference is that GOT slot.
- The proceed function has **2 direct `E8` callers** (both verified by
  objdump, both passing `(struct+0x20, stack pair)` like the coop callee
  does): `0x5a34bbc` (FDE `0x5a34440..0x5a3539f`) and `0x5a35859` (FDE
  `0x5a35480..0x5a35f48`), plus the coop callee's tail jump. It has no
  relocated-data reference. Those two callers are cited as context only;
  their bodies are not decoded here.
- Location records (all resolved through RELATIVE relocation addends; the
  file-pointer slots are zero and the addend is authoritative):
  `coop/mod.rs:397:13` (slot `0x64c6648`), `worker.rs:922:22` (slot
  `0x64c6380`), `defer.rs:16:42` (slot `0x64c6de8`).

## Where the chain goes cold (honest boundary)

Both direct callers of the characterized conversion instance pass their own
second argument through, so the ultimate producer of `P` is one hop further
up — and there the trail ends by direct control flow: the state machine
(`0x15d6e00`) and caller-2 (`0x15d5b00`) have **0 direct `E8` callers, 0
`lea` sites, and no `.text` instruction referencing their data slots**.
Each has exactly one relocated-data reference: slot `0x64014c0` (state
machine) and slot `0x6401300` (caller-2), each sitting immediately before
`lu.rs` Location records (`0x64014c8` = `lu.rs:220:26`,
`0x6401308` = `lu.rs:159:64`). Whoever consumes those slots does not
address them directly from `.text`, so the indirect caller — and with it
the ultimate producer of `P` — is not identified here.

## What this does not claim

- The Rust type/function names of `0x5cf3b90`, `0x5cfc310`, `P`, or `Q`
  are not asserted; "Tokio coop machinery" rests on the three vendored
  Location records plus the TLS/budget structure, not on a symbol name.
- The table slot `+0x8` is never called on observed paths; its role is open.
- The nonzero-guard-entry composition of the `0x5cfc3a6` block (its
  `r14`/`r15` uses are set only on the main flow) is not resolved; the
  guard itself (0 between calls, `-1` transient) is observed.
- The consumer of the `0x64014c0`/`0x6401300` function-pointer slots, and
  hence the ultimate producer of the context pointer, is not identified.
- No gate is requested by this packet; the next question is what the table's
  slot `+0x8` does, and which code consumes the two function-pointer slots
  to reach the state machine and caller-2 indirectly.
