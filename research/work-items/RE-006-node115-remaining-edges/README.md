# RE-006 node 115: the gate's remaining edges — branchless-select callers, the register-flag site, and the panic-formatting callee

PR #2608 pinned the gate callee behind slot `0x64e71b8` (a
checked decimal-scaling primitive) and left five open edges.
PR #2652 answered edge 2 (the inner bodies' caller census) and
PR #2698 traced edge 1 as far as the ctx forwarding goes. This
packet answers the three edges #2652 carried over unchanged:

3. the branchless-select callers: which running value the
   gate's `rdx` conditionally replaces in each, and whether a
   0 return leaves a stale value or a defined default;
4. the one register-supplied flag site (`0x3698891`): where
   its `r14b` comes from — when that caller asks for ceiling
   instead of floor;
5. the panic-formatting callee `0x1680e60` behind slot
   `0x64df730`, shared by every unwrap stub of the gate's
   shape.

Headline answers:

- **Edge 3 — a 0 return always leaves the defined default 0,
  never a stale value.** Under the rule stated below there are
  22 branchless gate sites in 20 FDEs (all with flag 0). In
  every one, the cmov's destination — or the register it is
  conditionally overwritten from — is zero-initialised in the
  rows immediately around the call. On success the gate's
  `rdx` replaces that 0; on failure the 0 stands. #2608's
  count of 15 used a narrower window (a cmov within the first
  three rows after the call); the 15 are a subset of the 22.
- **Edge 4 — `r14b` is a per-element source selector, written
  at exactly two rows.** It is set to 1 at `0x3698770` on the
  arm where the caller takes the element from its own cursor
  walk and advances the walk, and zeroed at `0x36987ac` on
  the arm where the walk is exhausted and the element arrives
  through a fallback lookup (`0x4505030`). Ceiling is
  therefore requested exactly for walk-sourced elements. The
  same byte, inverted, also selects which field the caller
  multiplies (`[rbp+0x58]` for the ceiling arm, `[rbp+0x78]`
  for the floor arm — the same two fields the inner bodies'
  two per-item calls use), gates the caller's own inline
  ceiling adjustment of its divider quotient, and keys a
  further cmov after the gate call.
- **Edge 5 — the "panic-formatting callee" is a chain of
  four small shims into a 154-byte consumer.** `0x1680e60`
  (18 B) rewrites its length argument to `2*len+1` and calls
  `0x1680e80` (44 B), which assembles a 0x28-byte frame
  record `{&{ptr, 2*len+1}, location, word 1}` and calls
  `0x5c826c0` (29 B), which rewraps the record and calls the
  9-byte tail shim `0x5c78380`, which direct-calls the
  consumer `0x5c812d0` (154 B). The consumer recovers
  `(ptr, len)` by shifting the tagged word back (`shr $1`),
  calls the formatting body behind slot `0x64ec640`
  (`0x5c9b316`, boundary), optionally calls the body behind
  slot `0x64df4a0` (`0x635de30`, boundary) with the message,
  and exits through the `.plt` stub at `0x63f0a50`. No body
  in the chain contains a `ret`; every one is followed by
  `int3`. The slot is called from 11,085 raw call candidates
  in 6,969 FDEs — it is the binary's shared panic entry, not
  an unwrap-specific helper — and the gate's 25-byte unwrap
  stub (`0x1680c10`) is the *only* FDE of its exact six-row
  shape among the validated small callers.

Target artifact: HL node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(105,896,032 bytes). Every address below is a virtual address
in that artifact; every body is pinned by FDE extent and
SHA-256 digest, and every file offset is resolved through the
section table (`.rodata` identity-mapped, `.text` delta
`0x1000`, `.data.rel.ro` delta `0x2000`). Slot references are
resolved from raw instruction bytes, never from objdump
comments.

## Edge 3: the branchless-select callers

Method. The #2608 census is re-derived: a raw byte scan of
`.text` for every rip-relative reference form targeting slot
`0x64e71b8` gives 89 candidates, all `call`, in 43 FDEs; each
candidate is validated against the decoded rows of its
containing FDE (0 false positives, matching #2608: flag
immediate 0 at 64 sites, immediate 1 at 24, register-supplied
at exactly 1).

A site is **branchless** when, in the rows after the call (up
to the next call, at most 10 rows), a `cmov` consuming the
result appears before any conditional branch, with a `test`
of the return value before the cmov. 22 sites in 20 FDEs
qualify; the other 67 sites branch on the return first. All
22 carry flag 0.

At every one of the 22, the value a successful gate call
replaces is a freshly written 0, in one of five shapes
(per-site pins — cmov row, zeroing row, first destination
read — are in `records.json`):

| class | sites | shape | value on gate return 0 |
| --- | --- | --- | --- |
| zeroed-dst | 12 | `xor %dst,%dst` before the call; `test $0x1,%al`; `cmovne %rdx,%dst` | `dst` keeps 0 |
| rdx-self-zero | 4 | `mov %rdx,%rcx`; `xor %edx,%edx`; `test`; `cmovne %rcx,%rdx` | `rdx` = 0 |
| copy-zero-on-eq | 2 | `mov %rdx,%rbp`; `test`; `mov $0x0,%eax`; `cmove %rax,%rbp` | `rbp` = 0 |
| rdx-zero-on-eq | 3 | `test`; `cmove %zero,%rdx` with the source zeroed in the window or just before the call | `rdx` = 0 |
| rax-zero-return | 1 | `mov %rax,%rcx`; `xor %eax,%eax`; `test $0x1,%cl`; `cmovne %rdx,%rax` | `rax` = 0 (the helper's return value) |

The 22 sites: `0x2bfbaa3`, `0x2bfbfe5`, `0x2bfd1a1`,
`0x2bfd2a6`, `0x2c01f94`, `0x2c32d37`, `0x2c37133`,
`0x3bfa2a8`, `0x4215436`, `0x421553c`, `0x54e2b88`,
`0x54e3298`, `0x54e3914`, `0x54e40d4`, `0x54e608d`,
`0x54e634d`, `0x54eeeec`, `0x54ef0fc`, `0x5575a57`,
`0x5576337`, `0x557e569`, `0x557f923`.

Reading of the result: these callers compute a per-element
converted quantity with an explicit "not convertible → 0"
convention. The zeroing is part of the idiom, written for
every element immediately before its gate call, so the
question #2608 left open — stale value or defined default —
is answered uniformly: **defined default 0**. After the
cmov, the destination's first read is a sign test
(`test %dst,%dst`) at 16 of the 22 sites (the converted
value is range-checked before use); at `0x4215436` it is
stored to the frame, at `0x421553c` shifted, and at
`0x2c37133`, `0x3bfa2a8`, `0x557e569`, `0x557f923` the first
read lies beyond the pinned window (recorded as null in
`records.json`, not extrapolated).

Boundaries: what each caller does with the converted value
after that first read — which accumulator or field it lands
in — is not traced here; several of these FDEs are large
loop bodies whose per-element flow is a separate question.

## Edge 4: the register-supplied flag site

The site `0x3698891` is the only register-flag site among
the 89 (re-derived above) and the only gate site in its FDE
`0x36961e0..0x3698ed2` (11,506 B, digest-pinned; the rows
below are pinned individually in `records.json`).

The caller walks a list with cursor `r13` (loop head
`0x369874d`). Per element, exactly two arms converge at
`0x36987af`, and between the loop head and the gate site the
only writes to `r14` are the two flag writes:

- **Walk arm (flag 1).** The element word is loaded from the
  cursor (`mov (%r13),%rcx` at `0x3698760`), the saved
  cursor advances, and `0x3698770` writes `mov $0x1,%r14b`.
- **Lookup arm (flag 0).** The cursor equals the end marker
  at `[rsp+0xd0]` (or is null): the caller instead calls the
  lookup body `0x4505030` (70 B, boundary) at `0x3698798`;
  on success it takes `rcx = (%rax)`, `r13 = rdx`, and
  `0x36987ac` writes `xor %r14d,%r14d`. If the lookup fails
  or the mode word at `[rsp+0x80]` is not 3, the iteration
  leaves through `0x3698a82` and never reaches the gate
  site — so every path that reaches the site has passed
  exactly one of the two writes in this iteration.

After convergence both arms share: an accessor call
(`0x3cc6670`, 260 B, boundary) yields the element record in
`rbp`; the caller's divider call (slot `0x64dfaf8`, the same
128-bit divider the gate family uses) computes a quotient
of a product over 10^14; and the flag byte is used three
more times around the gate call:

1. **Field select (inverted).** `ecx = r14d ^ 1`, shifted
   left 5: the multiplicand is `mulq 0x58(%rbp,%rcx,1)` —
   `[rbp+0x58]` on the ceiling arm, `[rbp+0x78]` on the
   floor arm. These are the same two element fields the
   inner bodies' flag-1 and flag-0 per-item calls scale.
2. **Inline ceiling adjustment.** At `0x3698818`,
   `test %r14b,%r14b` skips the caller's own remainder-based
   round-up of the divider quotient when the flag is 0 —
   the same pre-adjustment the inner bodies apply on their
   flag-1 term.
3. **Post-call select.** After the gate returns 1, its
   `rdx` is kept in `rbx`; at `0x36988ad` the same `r14b`
   keys a `cmovne` that picks between two frame values.

At the site itself the bindings are the family shape:
`rdi` = the (possibly pre-adjusted) quotient at
`[rsp+0x40]`, `rsi` = the element word at `[rsp+0x18]`,
`rdx` = `[rbp+0x10]` (the element's +0x10 field), `r8` =
the frame-saved table at `[rsp+0x68]`, and
`rcx` = `movzbl %r14b,%ecx` at `0x3698879`. A return ≠ 1
branches to `0x3698aeb` (the caller's failure arm).

So the answer to "when does this caller ask for ceiling":
exactly when the element it is converting came out of its
own list walk — the walk arm is the caller's primary
enumeration, and the lookup arm is a fallback for the
remainder, converted with floor. The static evidence does
not name what distinguishes the two element sources at
source level; the lookup and accessor bodies are
digest-pinned boundaries, not traced.

## Edge 5: the panic-formatting callee

Slot `0x64df730` holds exactly one relocation
(`R_X86_64_RELATIVE`, addend `0x1680e60`, initialised
content 0), and that addend is the *only* relocation in the
binary naming the body: there are no direct (E8) calls to
`0x1680e60` or `0x1680e80` anywhere in `.text`. The chain
(all five bodies exported in full):

| body | size | what it does |
| --- | --- | --- |
| `0x1680e60` | 18 B | `rsi := 2*rsi + 1` (`lea 0x1(,%rsi,2),%rsi`), then calls slot `0x64df6b8` → `0x1680e80`. `rdi` (message pointer) and `rdx` (Location descriptor) pass through untouched. |
| `0x1680e80` | 44 B | Builds a 0x28-byte frame record: `{ptr, tagged-len}` pair at `rbp-0x10`, then `{&pair, location, word 1}` at `rbp-0x28`; calls slot `0x64e1f30` → `0x5c826c0` with `rdi` = the record. |
| `0x5c826c0` | 29 B | Copies the record's first 16 bytes into a new frame pair together with a pointer to the original record; calls slot `0x64ec5d8` → `0x5c78380`. |
| `0x5c78380` | 9 B | Prologue only; direct-calls `0x5c812d0`. |
| `0x5c812d0` | 154 B | The consumer (below). |

The consumer reads the pair through the record: `rcx =
[rdi]`, and tests bit 0 of the tagged word `[rcx+8]` — the
`2*len+1` tag the first shim wrote. On the odd arm (the
only arm the unwrap stubs can produce) it recovers the
message pointer (`[rcx]`) and the true length (`tagged >>
1`), then calls the formatting body behind slot `0x64ec640`
with `rsi` = a static descriptor in `.data.rel.ro` (the
even arm's at `0x64031c0`, the odd arm's at `0x6403188`),
`rdx` = the Location pointer, and `ecx`/`r8d` = the two
bytes at `location+0x10` / `location+0x11`. After that
call, on the odd arm only, it calls the body behind slot
`0x64df4a0` with the recovered pair (`rdi` = length,
`rsi` = pointer, `rdx` = 0) — skipped when the stored
pointer word tests ≤ 0 as a signed value — and finishes
with a direct call to the `.plt` stub at `0x63f0a50`
(jump through slot
`0x64e2180`, `R_X86_64_RELATIVE` addend `0x16a0650` —
boundary). On the even arm it substitutes the sentinel
second word `0x8000000000000000` for the pair, makes the
same formatting call, and ends in `ud2` at `0x5c81318`.

Caller census of the slot: a raw scan of `.text` finds
**11,085** rip-relative references, **all `call`**, in
**6,969** distinct FDEs; no `jmp`, load or `lea` form
occurs. The raw scan is a superset of every
instruction-boundary reference; the candidates inside
owner FDEs of at most 64 bytes — 150 FDEs, 150 sites — were
all validated against decoded rows with zero mismatches.
The remaining candidates sit in larger bodies and are
reported as the raw superset count, not as validated
sites. Among the validated small callers, exactly one FDE
has the gate unwrap stub's exact six-row shape
(`push rbp; mov rsp,rbp; mov rdi,rdx; lea <message>; mov
<len>,%esi; call slot`): the stub `0x1680c10` itself. The
slot is therefore the shared panic entry for the whole
binary — thousands of distinct panic call sites — and the
unwrap stubs 
...[truncated 2771 chars]