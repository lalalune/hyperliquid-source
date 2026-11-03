# RE-001: map node #115 drain driver 0x5f14180 with its prepare and refresh callees

## Bounded question

Who drives the predicate-gated drain mapped by #2236, what runs before
and after it, and what observable state changes besides the drain
itself? This packet pins the whole behavior end to end — not a
lone-window fragment: the 122-byte driver whole, its 101-byte prepare
callee whole, its 41-byte refresh callee whole, the landing-pad
cleanup the prepare's unwind path reaches, and the driver's sole
census-confirmed caller with the branch it takes on the return value.

## Windows

- Driver: 0x5f14180..0x5f141fa (122 bytes), FDE at .eh_frame offset
  0x359364, length 0x30, CIE 0 (no LSDA). The window ends at the
  `__stack_chk_fail` call at 0x5f141f5; the `int3` padding from
  0x5f141fa and the next function at 0x5f14200 are excluded.
- Prepare: 0x5f13f90..0x5f13ff5 (101 bytes), FDE at .eh_frame offset
  0x745f7c, length 0x38, CIE 0x730230 with LSDA augmentation. The
  window ends at the landing-pad jump at 0x5f13ff0; the `int3`
  padding from 0x5f13ff5 and the next function at 0x5f14000 are
  excluded.
- Refresh: 0x5f13450..0x5f13479 (41 bytes), FDE at .eh_frame offset
  0x3591a8, length 0x18, CIE 0 (no LSDA). The window ends at the `ret`
  at 0x5f13478; the `int3` padding at 0x5f13479 and the next function
  at 0x5f13480 are excluded.
- Landing-pad cleanup: 0x5f13f72..0x5f13f87 (21 bytes), no FDE of its
  own. It is the target of the prepare's landing-pad jump at
  0x5f13ff0: it deletes the fresh 0x50-byte allocation and resumes
  the unwind. It is included as a supplementary excerpt, not as a
  separate function.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x5f14180 --stop-address=0x5f141fa work/hl-node-115.bin
objdump -d --start-address=0x5f13f90 --stop-address=0x5f13ff5 work/hl-node-115.bin
objdump -d --start-address=0x5f13450 --stop-address=0x5f13479 work/hl-node-115.bin
objdump -d --start-address=0x5f13f72 --stop-address=0x5f13f87 work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. All four
windows start with `endbr64` except the cleanup block, which is not a
function entry; every mnemonic in the excerpts is genuine objdump
output from the target binary, not a placeholder, and verify.py
checks sampled instructions byte-for-byte against a fresh objdump run
and the raw binary. Instruction-level detail lives only in the
verbatim excerpts; records.json carries semantic records, not a
per-instruction list.

## Semantics (literal)

### Driver 0x5f14180

Arguments: rdi = outer object, rsi = collection, rdx = predicate
argument. Returns the drain's int result (0 when nothing was popped,
1 once at least one node has been popped, per #2236).

```
prepare(outer, collection, predicate_arg)   # 0x5f13f90, args forwarded unchanged
inner = [outer + 0x08]                      # re-read AFTER prepare: prepare may replace it
popped = drain(inner, collection, predicate_arg)  # 0x5f14000, mapped by #2236
refresh(outer)                              # 0x5f13450
if byte [outer + 0x01] == 1:                # lock cmpxchg at 0x5f141cf
    byte [outer + 0x01] = 0
# any other value at [outer + 0x01] is left unchanged
return popped
```

Notes, stated literally:

- The prepare call forwards all three arguments unchanged, but the
  prepare itself reads only the outer object (see below); the
  collection and predicate argument pass through it untouched.
- The drain's object is the post-prepare inner object, not the
  pre-prepare one: the driver reloads [outer + 0x08] after the
  prepare returns, so a copy-on-write swap changes what gets drained.
- The flag step is a single `lock cmpxchg` (eax = 1, edx = 0): when
  the byte at [outer + 0x01] equals 1 it is written to 0; otherwise
  the old byte is copied into a stack byte at rsp + 0x07 that is
  never read afterwards, so the only observable effect is the
  conditional clear of a byte that is exactly 1.
- A stack canary is used (loaded from %fs:0x28 into rsp + 0x08,
  checked before return; mismatch calls `__stack_chk_fail` at
  0x5f141f5, which does not return). No rip-relative reference
  appears in-window. The only PLT call in-window is
  `__stack_chk_fail`.

### Prepare 0x5f13f90 (copy-on-write swap, read whole)

Arguments: rdi = outer object (rsi/rdx forwarded, never read).
Returns void.

```
inner = [outer + 0x08]
if dword [inner + 0x40] == 1:
    return                                  # sole-owner fast path: nothing changes
new = operator_new(0x50)                    # PLT call at 0x5f13fb8
move(new, outer + 0x18, inner)              # 0x5f12840, by contract only (see below)
[outer + 0x08] = new
init(new)                                   # 0x5f12a00, by contract only
release(old = inner, 0)                     # tail jump at 0x5f13fe4 to 0x5f13ea0
```

Notes, stated literally:

- The +0x40 field is a reference count: 0x5f13ea0 first decrements
  [old + 0x40] and returns at once when the result is nonzero; only
  on zero does it run its destroy path (transfer-draining both
  lists, deleting the nodes and the 0x50-byte object). That
  decrement-and-branch was read in 0x5f13ea0's window this cycle;
  the move helper 0x5f12840 and the init helper 0x5f12a00 were not
  read, so only their call sites and argument registers are claimed
  (the 0x5f12840/0x5f12320 list-move area was judged too tangled to
  pin honestly in earlier cycles).
- The release call passes 0 as its second argument. What the
  destroy path's transfer calls do with that argument when a payload
  count reaches zero is not claimed here; only the decrement branch
  and the call sites are claimed.
- From prepare alone, the destroy-on-zero branch cannot trigger:
  the fast path returns exactly when the count is 1, and any other
  count decrements to a nonzero value (2 or more to 1 or more, 0
  to -1). The destroy branch is exercised by 0x5f13ea0's direct
  callers (0x5d8ffcf, 0x5d9110a), not by prepare.
- The move helper 0x5f12840 has exactly one caller file-wide: this
  prepare's call site at 0x5f13fca.
- Unwind path: the landing pad at 0x5f13fe9 jumps to the cleanup
  block at 0x5f13f72, which operator-deletes the fresh 0x50-byte
  allocation and calls `_Unwind_Resume`. No other landing pad
  exists in-window.

### Refresh 0x5f13450 (aggregate cache + nonempty byte, read whole)

Arguments: rdi = outer object. Returns void.

```
inner = [outer + 0x08]
[outer + 0x20] = aggregate(inner)           # 0x5f13130, two-list aggregate mapped by #2182
[outer + 0x28] = 1 if [inner + 0x18] != inner + 0x18 else 0
```

Notes, stated literally:

- The +0x28 byte is 1 exactly when the list headed at inner + 0x18
  is nonempty: the compare is the header's first-node pointer
  [inner + 0x18] against the header address itself (setne).
- No PLT call, no stack canary, no rip-relative reference
  in-window; the only call is the direct call to 0x5f13130.

## Consumers (call sites only; containing-function internals not read)

- Driver 0x5f14180, sole caller: 0x5e892a8 inside
  0x5e89100..0x5e894f9. It passes rdi = r15, rsi = r14 + 0x218, and
  rdx computed from earlier registers, then immediately tests the
  returned byte (`test %al,%al` at 0x5e892ad; zero jumps away to
  0x5e8938d, nonzero proceeds). Nothing else about the caller is
  claimed.
- Prepare 0x5f13f90, six direct calls file-wide: 0x5f140e5 (in the
  sibling driver 0x5f140c0), 0x5f141a5 (this driver), 0x5f143b5,
  0x5f1468e, 0x5f15a43, 0x5f15a9a. Only the in-window site
  0x5f141a5 is claimed in detail; the others are census sites.
- Refresh 0x5f13450, seven direct calls file-wide: 0x5f1412d (in the
  sibling driver 0x5f140c0), 0x5f141be (this driver), 0x5f14545,
  0x5f145cf, 0x5f147c0, 0x5f16472, 0x5f165bf. Only the in-window site
  0x5f141be is claimed in detail; the others are census sites.

## Unknowns, stated explicitly

- The meaning (name) of the flag byte at outer + 0x01 is unknown;
  only its conditional-clear behavior is pinned.
- The field-by-field contents moved by 0x5f12840 and established by
  0x5f12a00 are unknown; both are by contract only.
- Whether the driver's caller at 0x5e892a8 runs before or after other
  operations on the same object is unknown; only its call site and
  its immediate return test are claimed.
