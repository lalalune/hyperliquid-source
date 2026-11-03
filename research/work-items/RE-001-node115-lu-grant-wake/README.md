# RE-001-node115-lu-grant-wake

## Claim status: observation

This packet answers packet #192's (PR #2234) explicitly stated next
question (a): **who writes waiter node +0x10 = 1** — the writer completing
#192's RwLock read wait and #190's timed-wait first phase.

The writer is FDE `0x5bb35f0..0x5bb3c94` (1700 bytes) in node #115. Its
reset loop stores `[node+0x10] = bpl` (the grant flag) into every
collected waiter node and then futex-wakes each node's `+0x20` word.
When `bpl = 1`, the waiter observes `+0x10 == 1` and proceeds (returns 1
in #192's wait, advances to phase 2 in #190's wait). When `bpl = 0`, the
waiter observes `+0x10 == 0` and retries. The grant flag is computed as
`bpl = (esi_low_byte OR deadline_refreshed) AND nodes_present`.

## Scope

Included:

- The full FDE `0x5bb35f0..0x5bb3c94`: bucket claim, bucket-list walk
  and unlink, SmallVec collection, bucket-deadline check/refresh,
  slot-word rewrite, reset loop, bucket release, wake staging, and the
  futex wake loop.
- The grant computation (`or bpl,cl` / `and bpl,al`), the slot-word
  rewrite, the reset-loop stores, and the wake loop with its flag-2 skip.
- The caller census: 0 direct E8 callers, 66 GOT-indirect sites (65 call,
  1 tail-call jmp) via slot `0x64e1000` across 26 FDEs.
- The panic provenance: parking_lot.rs, raw_rwlock.rs, smallvec, and the
  40-byte `overflow when adding duration to instant` message.

Excluded:

- The callees' internals: table creation `0x5bb6400`, vector grow
  `0x5bb5450`, clock wrapper `0x5c842e0`, cleanup `0x5bb66b0` (already
  packetized in #188/#189 as the FIFO cleanup waker), and contention
  helper `0x5bb6790` (#189). They are referenced by address and GOT slot
  only.
- The caller-side role of each of the 66 GOT call sites (which unlock or
  timeout path calls this function, and with what `esi`). Three sites
  were sampled; all pass `esi = 0`. No `esi = 1` caller is identified.
- Any runtime behavior. Analysis is static only; the node binary was
  never executed.

## Reproduce

Worktree base: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
(node-115-only). Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got` file offset =
VA − 0x2000; `.rodata` file offset = VA.

```
objdump -d --start-address=0x5bb35f0 --stop-address=0x5bb3c94 \
  artifacts/node/115/hl-node > fde35f0.objdump.txt
python3 tools/node115_lu_grant_wake.py
python3 -m pytest tests/test_node115_lu_grant_wake.py -q
```

The verifier reads bytes only and exits 0 on pass. It checks the binary
digest, the exact FDE bytes, opcode spot checks, ELF relocation addends,
panic Location structs, the packet hex reference, the packet records, and
the caller census.

## Evidence

### FDE shape

- Range `0x5bb35f0..0x5bb3c94` = 1700 bytes; body proper to the single
  `ret` at `0x5bb3bc8` = 1497 bytes; tail (cleanup landing pad, panic
  stubs, unwind pads) = 203 bytes. 1497 + 203 = 1700.
- 446 instructions: 402 in the body, 44 in the tail; 5 nop paddings
  (all in the body: `0x5bb3639`, `0x5bb3739`, `0x5bb397c`, `0x5bb39b8`,
  `0x5bb3b64`). Body SHA-256 (hash-pinned, no normalization):
  `026fbc7f26d2434e257dc9cbe5f7aa75a7afe89dace5cc3c541961d144d28e75`.
- CIE `0x39672c` (zPLR), the same CIE as #192's FDE.

### Signature and bucket claim

`f(rdi = slot pointer, esi = grant flag)`. `rdi` is saved to `[rsp+0x8]`
and used both as the hash key and as the slot whose word is rewritten;
`esi` is saved to `[rsp+0x14]` and only its low byte is ever used (as
`bpl`). The bucket claim is the #188 lookup shape: golden-ratio hash
(`movabs r14,0x9e3779b97f4a7c15` at `0x5bb3605`, `imul r14,rdi`,
`shr` by `64 - [table+0x18]`), 64-byte stride, `lock cmpxchg entry,1`
at `0x5bb3681` with `ebp = 1`, contention helper `0x5bb6790` (#189)
on race via GOT `0x64ec160`, table creation `0x5bb6400` on null via
GOT `0x64ec158`, release-and-retry on table change (`lock xadd -1`
at `0x5bb3699`, cleanup on `(old&2)==0 AND old>=4`). The table-pointer
static is `0x64fff28` — the same static #188's lookup uses — reached
here via GOT slot `0x64ec148` (relocation addend `0x64fff28`).

### Walk and collection

The walk starts at the bucket head `[rbx+0x8]`, follows `+0x8` links,
and unlinks every node whose key equals the slot (`[prev_link] = next`
at `0x5bb3799`, tail fixup `[rbx+0x10] = prev` at `0x5bb37a2`). Nodes
are pushed into a SmallVec of 24-byte `{node, flag, futex-ptr}` entries
(entry node store at `0x5bb37e9`, flag `0` at the next qword), inline
capacity 8 at `[rsp+0x18]`, heap grow via `0x5bb5450` on the 9th push
(`0x5bb381a`), heap base `[[rsp+0x18]]` thereafter, heap storage freed
via GOT `0x64df4a0` when count ≥ 9 (`0x5bb3bb1`). The count is at
`[rsp+0xd8]`; the effective count is `[rsp+0xd8]` unless that value is
greater than 9, in which case it is `[rsp+0x20]` (cmovae at
`0x5bb3866-0x5bb386d` and `0x5bb3918-0x5bb3923`).

An accumulator tracks the sum of collected nodes' `+0x18` values
(`add r13,rax` at `0x5bb3790`; `rax = r13` after each push). Two
branches gate collection on the accumulator's low byte, tested before
each matching node:

- Bit 3 set (`test al,0x8` at `0x5bb376a`) → the walk aborts at
  `0x5bb3850` with `[rsp]` set to the current node's link address.
- Bit 2 set (`test al,0x4` at `0x5bb3777`) and the node's `+0x18` has
  bits `0xc` set → the node is skipped (not collected) and the walk
  flag's low byte is set to 1 (`mov al,0x1` at `0x5bb3786`,
  `[rsp] = rax` at `0x5bb3788`).

For the known waiter shapes (`+0x18` in `{0, 8, 0x10}`), the bit-2 branch
never fires (no sum of those values sets bit 2). The bit-3 branch does
fire for 8-valued nodes: after one 8-valued node is collected the sum
is 8 (bit 3 set), so the next matching node aborts the walk. For
uniform `0x10`-valued nodes (#192 shape) the sum never sets bit 3 and
the walk collects every matching node. The semantic reason for the
bit-2/bit-3 gates is not established; the branches are reported
mechanically.

### Deadline check and the grant flag

If the vector is nonempty, the bucket deadline (`[rbx+0x18]` seconds,
`[rbx+0x20]` nanoseconds, `[rbx+0x28]` xorshift seed) is compared
against now from the clock wrapper `0x5c842e0` (`edi = 1` at
`0x5bb387a`). If now exceeds the deadline, the deadline is refreshed
with the #188/#190 shape — xorshift32 (13/17/5 at `0x5bb38b0` /
`0x5bb38b7` / `0x5bb38be`), jitter `(seed * 0x431bde83 >> 50) mod 10^6`
(magic `0x431bde83`, shift 50, mod `10^6`), carry into seconds on
reaching `10^9` with a signed-overflow panic — and `cl = 1`
(`0x5bb38fb`). Otherwise `al = 1`, `cl = 0` (`0x5bb3896-0x5bb3898`).
If the vector is empty, `al = 0`, `cl = 0` (`0x5bb389c-0x5bb389e`).

The grant flag is then `bpl = (esi_low_byte OR cl) AND al`
(`or bpl,cl` at `0x5bb38fd`, `and bpl,al` at `0x5bb3902`). So `bpl = 1`
exactly when at least one node was collected AND (the caller's `esi`
flag is set OR now exceeded the bucket deadline). The three sampled
callers all pass `esi = 0`, so for them the grant comes only from the
deadline-refresh path: a wake issued after the bucket deadline has
passed grants the waiters; a wake issued before it does not.

### Slot-word rewrite

`[slot] = (accumulator if bpl else 0) | walk_flag_low_byte`
(`cmovne rcx,r13` at `0x5bb3905`, `movzx eax,r8b` at `0x5bb3909`,
`mov [rax],rcx` at `0x5bb3915` where `rax = [rsp+0x8]` = the slot).
On mainline the walk flag is 0, so a granting call writes the `+0x18`
sum and a non-granting call writes 0. For uniform `+0x18 = 0x10` nodes
(#192 shape) the sum equals `0x10 × count`, i.e. the RwLock reader
count in units of `0x10` — consistent with granting N readers — but
the reader-count reading is an interpretation, established only for
uniform `0x10`-valued nodes; mixed-shape sums are not resolved. When
the bucket list is empty the slot word is still rewritten, to 0
(`bpl = 0`, flag `0`).

### Reset loop: the +0x10 = 1 writer

`movzx edi,bpl` at `0x5bb393e`, then for every collected entry:

- `[node+0x10] = rdi` — scalar store at `0x5bb3983`, unrolled ×4
  stores at `0x5bb39c3`, `0x5bb39e5`, `0x5bb3a08`, `0x5bb3a2b`.
- `[node+0x20] = 0` — scalar at `0x5bb398a` and unrolled twins.
- `[entry+0x8] = 1` — scalar at `0x5bb3996` and unrolled twins.
- `[entry+0x10] = &node+0x20` — scalar at `0x5bb399e` and unrolled
  twins.

This is the answer to #192's question (a): the reset loop is the only
writer of waiter `+0x10 = 1` found in the family census and in the
whole-binary `mov [reg+0x10],0x1` scan (see Limitations). The reset
loop handles both the inline base (`lea rsi,[rsp+0x18]` at `0x5bb3930`)
and the heap base (`mov rsi,[rsp+0x18]` at `0x5bb391e`, taken when
count ≥ 9).

### Release and wake

Bucket release at `0x5bb3a57`: `lock xadd [rbx],-1`, cleanup
(`0x5bb66b0` via GOT `0x64ec150`, landing pad `0x5bb3bc9`) exactly
when `(old&2)==0 AND old>=4` — the same release idiom as #188/#189.
A `0xb0`-byte memcpy (GOT `0x64df508` at `0x5bb3a95`, src `[rsp+0x28]`,
dst `[rsp+0xf0]`) stages the collected entries into a second stack
array. The copy is shifted by 16 bytes relative to the vector because
the first entry's flag is held separately at `[rsp+0xe8]` and the wake
loop reads only (flag, futex-ptr) pairs at 24-byte stride — it never
reads the node pointers again.

The wake loop (base `r13`, `rbx = r13+0x10`, 24-byte stride) skips
entries whose `[entry+0x8] == 2` (`cmp [rbx-0x8],0x2` at `0x5bb3b1b`);
no path sets flag 2 (collection sets 0, reset sets 1), so every entry
is woken on mainline. Each wake is `syscall(202, rsi, 0x81, 1)`:
`rsi = [rbx]` = `&node+0x20` (`0x5bb3b22`), `mov edi,0xca` = 202
(`0x5bb3b25`), `mov edx,0x81` = FUTEX_PRIVATE_FLAG|FUTEX_WAKE
(`0x5bb3b2a`), `mov ecx,1` (`0x5bb3b2f`), `call r15` (`0x5bb3b36`)
with `r15` loaded from the syscall GOT slot `0x64e06b8` (`0x5bb3b07`).
A second loop (`0x5bb3b70-0x5bb3b96`) applies the same flag-2 skip to
the remaining entries.

Return value: `rax` holds the collected count on the inline path
(`0x5bb3b98`); on the heap path `rax` is free's return value. Whether
any caller consumes the return value is not established.

### Caller census

- 0 direct E8 callers (every-position byte scan over all of `.text`).
- 66 GOT-indirect sites via slot `0x64e1000` (relocation addend
  `0x5bb35f0`): 65 `call [rip+disp]` and 1 tail-call `jmp [rip+disp]`
  (`0x4fb53e8`), across 26 FDEs. The every-position byte-scan count
  matches the objdump-boundary count exactly.
- Sampled callers (all pass `esi = 0`, `rdi` = slot pointer):
  `0x5ce74e3` (FDE `0x5ce7380`), `0x15471e3` (FDE `0x1546aa0`),
  `0x4fca510` (FDE `0x4fca1c0`).

### Panic provenance

All Location structs resolved via R_X86_64_RELATIVE addends in
`.data.rel.ro` (file offset = VA − 0x2000):

- `0x64bd260` parking_lot.rs:352:45 — subtract (`64 - [table+0x18]`
  underflow, `jb` at `0x5bb3652` → stub `0x5bb3bf2`, wrapper
  `0x64df848`).
- `0x64bd290` parking_lot.rs:363:23 — index bounds (hash-index check,
  `jae` at `0x5bb366e` → stub `0x5bb3bff`, wrapper `0x64df620`). Note:
  363, not #191's 390 — a separate site.
- `0x64bd278` parking_lot.rs:352:5 — shift (`shr` by ≥ 64, `jae` at
  `0x5bb365b` → stub `0x5bb3c0c`, wrapper `0x64e0820`).
- `0x64bd248` raw_rwlock.rs:963:31 — `+0x18` accumulator sum add
  overflow (`jb` at `0x5bb3793` → stub `0x5bb3c28`, wrapper
  `0x64df520`). The raw_rwlock.rs file is itself provenance that this
  function belongs to the RwLock family.
- `0x64bd2c0` smallvec lib.rs:1124:13 — vector count increment
  capacity overflow (`je` at `0x5bb37fd` → stub `0x5bb3c37`, wrapper
  `0x64df520`).
- `0x64bd478` smallvec lib.rs:2243:17 — second wake loop
  empty-remaining index (`je` at `0x5bb3b7a` → stub `0x5bb3c19`,
  wrapper `0x64df520`).
- Deadline seconds +1 signed overflow (`jo` at `0x5bb38e6` → stub
  `0x5bb3bd7`): 40-byte message `overflow when adding duration to
  instant` at `.rodata` `0x94a2c1`, length `esi = 0x28` = 40, wrapper
  `0x64df770` — the same message as #188's std time.rs:429:33
  overflow, here reached from the deadline-refresh path.

## Results and limitations

Verified counts: FDE 1700 bytes (1497 body + 203 tail), 446
instructions (402 body + 44 tail, 5 nop), 1 ret, 5 grant stores
(1 scalar + 4 unrolled), 1 futex wake site, 0 E8 callers, 66 GOT sites
(65 call + 1 jmp) across 26 FDEs, 3 sampled callers all passing
`esi = 0`, 7 panic sites.

Honest limitations:

- The caller-side meaning of `esi` beyond the mechanism is not fully
  established: no `esi = 1` caller was found in the 3-site sample, so
  the "grant" path is established mechanically and via deadline
  refresh, but a caller that grants explicitly is not identified.
- The bit-2/bit-3 walk gates are reported mechanically; why the
  accumulator gates collection that way is not established.
- The spill-time SmallVec field migration (which stack slot holds the
  count after the 9th push) is not fully resolved; the packet claims
  only the observed cmovae selection, not a field model.
- The slot-word `+0x18`-sum → reader-count reading holds only for
  uniform `0x10`-valued nodes; mixed-shape sums are unresolved.
- The wake-staging memcpy's 16-byte shift is described from the dump;
  the first entry's flag at `[rsp+0xe8]` is the compensating slot.
- The negative claim (no other `+0x10 = 1` writer) rests on the
  family-cluster census plus a whole-binary immediate-store scan
  (2024 `mov [reg+0x10],imm` hits; exactly one in the cluster range
  `0x5bb0000..0x5bc0000`, an `[rsp+0x10]` spill at `0x5bb6ba9`) and
  the intersection of true `mov [reg+0x10],0x1` stores with futex-WAKE
  FDEs (26 FDEs, none in the cluster except the rejected `0x5baaef0`
  teardown, which has no table variable, no golden-ratio hash, and no
  `+0x20` futex word). A writer using a non-immediate store (register
  source) would not appear in that scan; the reset loop here uses a
  register source (`rdi`) itself, so the scan is supporting evidence,
  not proof of uniqueness. The positive claim — this function writes
  `+0x10 = bpl` and wakes — is direct and does not depend on the scan.
- No gate is requested beyond the standard packet checks. The
  implementation/comparison section of EVIDENCE.md records the
  independent Rust path as not yet implemented.

## Next question

Which caller path grants explicitly (`esi = 1`), and what unlock or
timeout operation does it belong to — i.e. complete the caller-side
role of the 66 GOT sites, starting from the 26 caller FDEs listed in
records.json.
