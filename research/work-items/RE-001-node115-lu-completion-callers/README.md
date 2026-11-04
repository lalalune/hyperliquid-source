# RE-001-node115-lu-completion-callers

## Claim status: observation

This packet answers packet #199's (resolver) explicitly stated next
question: **census and decode the completion helper `0x4da86a0`'s
direct callers beyond the `0x4fb52e0` gate-release worked example —
which entry paths drive a tree removal through flag, resolver, and
completion, and what does each do with the 24-byte payload?**

## The answer

**1. There is no second direct caller. #195's census stands.**
A full-binary static census finds exactly one direct E8 caller of
the completion helper: the gate-release FDE at `0x4fb539e`
(bytes `e8 fd 32 df ff`). There are 0 E9 tail jumps to it, 0 GOT
sites, 0 relocation addends equal to it, 0 rip-relative LEA sites
taking its address, and 0 absolute 8-byte references to it in
`.data.rel.ro`, `.rodata`, `.data`, `.got`, `.got.plt`,
`.gcc_except_table`, `.eh_frame`, or `.eh_frame_hdr`. The only
static path that drives a tree removal through flag, resolver, and
completion is gate-release.

**2. Gate-release discards the 24-byte payload — provably.**
The completion call is set up with `lea rdi,[rsp+0x58]` at
`0x4fb5394` (a stack buffer address, not a loaded pointer) and
`lea rsi,[rsp+0x38]` at `0x4fb5399` (the copied loc). After the
call returns, gate-release executes no read of `rsp+0x58`,
`rsp+0x60`, or `rsp+0x68` before tearing the frame down
(`add rsp,0x70` at `0x4fb53b1`, `ret` at `0x4fb53ba`). The
24-byte payload (removed key, value, flag) is written to a dead
stack buffer and dies with the frame. The removal side effect —
unlink plus free on the tree path, memmove-shift plus count
decrement on the table path (#195) — is the whole point; the
returned triple is never consumed by its only caller.

**3. The near-miss entry path is a claim operation, not a removal.**
The flag helper's only other direct caller is the FDE at
`0x4fac710` (208 bytes, 67 instructions), a gate-guarded twin of
gate-release with the same slot protocol (0 → 8 acquire at
`0x4fac72d`, timed-wait fallback via GOT `0x64e0ff0` →
`0x5bb2440` with the 10^9-ns sentinel, 8 → 0 release at
`0x4fac77b`, release-failure grant-wake fallback via GOT
`0x64e1000` → `0x5bb35f0` with `esi = 0`). But its payload is
different: it calls the flag helper at `0x4fac740` (out at
`rsp+0x8`, no flag check — the result is passed on wholesale),
then calls the entry-cell resolver `0x4da6c80` at `0x4fac74a`
with the flag-out struct. It reads the returned count cell:
if the count is `>= 2` it writes NULL to the caller's out struct
and releases; otherwise it increments the count, lock-increments
the refcount at `[P]` (with a `jle` → `ud2` guard at `0x4fac762`
against resurrecting a dead object), and returns `{P, input
dword}`. It never calls the resolver or the completion helper,
so it claims entries (at most 2 concurrent claims per cell) but
removes nothing. Together the pair brackets the entry count:
acquire 0 → 1 → 2 (fail at `>= 2`), release 2 → 1 → 0
(removal at 0, #194).

**4. The entry-cell resolver converts flag-out into a count cell.**
The FDE at `0x4da6c80` (240 bytes, 71 instructions) takes the
flag-out struct and returns a pointer to the entry's count cell,
on all four flag/shape combinations:
- Flag `== 1`, node pointer nonzero (tree hit): return
  `node + position * 16` — the value slot, whose first qword is
  the count (`0x4da6ce9..0x4da6cf7`).
- Flag `== 1`, node pointer zero (small-table hit): bounds-check
  the key against table length (`[B+0x18]`), panic on
  `index >= capacity` with the same message, location struct,
  and GOT wrapper as gate-release's index panic (see below),
  then return `buffer + (key + head mod capacity) * 24 + 8`
  (`0x4da6d17..0x4da6d47`).
- Flag `!= 1`, node pointer nonzero (tree miss): build a 40-byte
  stack struct from the flag-out fields and call `0x51f3e20`
  (`rdi` = out pair, `rsi` = input struct, `edx = 0`, `ecx = 0`)
  at `0x4da6cd6`; if its out node is nonzero, apply the same
  `node + index * 16` formula, else fall to the table path with
  the table pointer from its out struct (`0x4da6d48`).
- Flag `!= 1`, node pointer zero (small miss): call `0x57ec1b0`
  (`rdi` = table, `rsi` = key, `rdx` = `{key, 0, flag-byte 0}`)
  at `0x4da6d12`, ignore its return, and compute the cell
  pointer from the table fields as in the small-hit path.
Its only direct caller is the acquire FDE (`0x4fac74a`); the two
delegates `0x51f3e20` and `0x57ec1b0` are each called only from
inside it (`0x4da6cd6`, `0x4da6d12`). Their internals are not
decoded here, only their call shapes.

**5. The shared panic pins both FDEs to one operation family.**
The cell resolver's bounds panic at `0x4da6d53` uses message
`0x9171a2` ("Out of bounds access", 20 bytes), location struct
`0x649cc08` (`base/src/l1_map/entry.rs`, line 64, col 17, file
string `0x4402cd` length 24), and GOT wrapper `0x64df770` →
`0x1680bd0` — the identical message, location struct, and
wrapper as gate-release's index panic at `0x4fb53ee` (#194).
Acquire and release are two operations of the same l1_map entry
API, not two unrelated callers that happen to share a helper.

## Scope

Included:

- The full FDE `0x4fac710..0x4fac7e0` (208 bytes; 67
  instructions: 41 body through `ret` at `0x4fac78f` + 26 tail;
  5 `int3` padding, 1 `ud2` guard, 0 nops).
- The full FDE `0x4da6c80..0x4da6d70` (240 bytes; 71
  instructions: 37 body through `ret` at `0x4da6cf7` + 34 tail;
  4 `int3` padding, 0 nops; 1 objdump byte-continuation line at
  `0x4da6d02` excluded from the strict count).
- The completion-caller census: 1 E8, 0 E9, 0 GOT, 0 relocation
  addends, 0 LEA address-taken, 0 absolute data references.
- The flag census (2 E8: `0x4fac740`, `0x4fb530f`) and the
  resolver census (1 E8: `0x4da86c9`), both confirming #195
  and #199 respectively.
- Entry signature of acquire: `f(out: *mut {P, input}, pcell:
  *const P, input: u32)`; out `{P @+0, input @+0x8}` (first
  qword zeroed, second untouched, on the full path).
- Entry signature of the cell resolver: `f(flag_out: *const
  FlagOut) -> *mut count_cell`; flag-out fields read: flag
  dword `@+0`, node `@+0x8`, table `@+0x10`, key/position
  `@+0x18`, key dword `@+0x20`, trailing qword `@+0x24`,
  trailing dword `@+0x2c`.

Excluded:

- The completion helper internals (claimed by #195 as
  `fde86a0`; only its call site and call setup are cited here,
  not re-claimed as bytes).
- The gate-release FDE internals (claimed by #194 as `fde52e0`;
  only the completion call setup and the post-call instruction
  sequence are cited here, not re-claimed as bytes).
- The flag, resolver, and leaf-op internals (claimed by
  #195/#199/#196; only their call sites are cited).
- The internals of `0x51f3e20`, `0x57ec1b0`, and `0x1680cab`
  (call shapes and GOT resolutions only).
- Any runtime behavior. Analysis is static only; the node binary
  was never executed.

## Reproduce

Worktree base: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
(node-115-only). Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got` file offset =
VA − 0x2000; `.rodata` file offset = VA.
Instruction counts are strict mnemonic-line counts: objdump lines
with an address, a byte field, a tab, and a mnemonic.
Byte-continuation lines (address + bytes only) are excluded.

```sh
objdump -d -M intel --start-address=0x4fac710 --stop-address=0x4fac7e0 \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x4da6c80 --stop-address=0x4da6d70 \
  artifacts/node/115/hl-node
python3 tools/node115_lu_completion_callers.py
python3 -m unittest tests.test_node115_lu_completion_callers -v
```

## What this changes about #194 and #195

- #194's records describe the completion call setup as
  "`rdi = [rsp+0x58]`" (a pointer load). The bytes say otherwise:
  `lea rdi,[rsp+0x58]` at `0x4fb5394` — the out buffer is
  gate-release's own stack slot `rsp+0x58..0x70`, and no
  instruction reads it after the call. #194's mechanism
  (count `<= 1` → completion) stands; only the operand form and
  the payload's fate are corrected and pinned: the 24-byte
  payload is dead on arrival.
- #195's completion census (exactly 1 direct E8 caller) is
  confirmed, not corrected: the full-binary scan reproduces it,
  extended with the E9, GOT, relocation, LEA, and absolute-data
  checks, all zero.
- #195 pinned the flag-out layout through field D at `+0x20`.
  The cell resolver reads trailing fields at `+0x24` (qword)
  and `+0x2c` (dword) on the tree-miss path, so the struct as
  read here is 48 bytes, not 40. This extends #195's layout; it
  does not refute it, since #195 never claimed the struct ends
  at `+0x28`.

## Limitations

- The "claim count capped at 2" reading follows from the
  `>= 2` → NULL branch plus the increment; the "refcount"
  reading of `[P]` follows from the `lock inc` plus the
  `jle` → `ud2` guard. No runtime trace confirms either label.
- The delegates `0x51f3e20` (tree-miss) and `0x57ec1b0`
  (small-miss) are characterized by call shape only; whether
  the small-miss delegate inserts the key or merely ensures
  presence is not established, since the cell resolver ignores
  its return and recomputes the pointer from the table fields.
- The unwind-path GOT call in acquire (`0x64df4c0` →
  `0x1680cab` at `0x4fac7d5`) is a landing-pad block whose
  callee identity is not decoded.
- No runtime behavior is claimed; the node binary was never executed.

## Next question

Census and decode the direct callers of the acquire/release pair
(`0x4fac710` / `0x4fb52e0`): which API operations claim and
release entries, and what do they do with acquire's NULL versus
`{P, input}` result?
