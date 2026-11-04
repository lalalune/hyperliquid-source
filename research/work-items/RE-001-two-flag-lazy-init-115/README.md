# RE-001: map node #115 two-flag lazy-init variant 0x605e8a0 with its callback, wrapper and callers

## Bounded question

The lazy-init callee mapped by #2244 (0x605e860) has a neighbouring
flag variant at 0x605e8a0 that #2244's census already noticed but
did not map: it calls 0x605e860 and then runs a second, independent
flag gate of its own. What does the variant do end to end, what does
its own callback (0x606a890) do before tail-delegating, and who calls
the variant and its forwarding wrapper? This packet pins the whole
behavior end to end — not a lone-window fragment: the 71-byte variant
whole, the 47-byte callback whole, the 18-byte wrapper whole, the
lazy-init call the variant makes into #2244's mapped function, and
every census-confirmed caller of the variant (three direct calls) and
consumer of the wrapper (one direct call, one tail jump).

## Windows

- Variant: 0x605e8a0..0x605e8e7 (71 bytes), FDE at .eh_frame offset
  0x367860, length 0x20, CIE 0 (no LSDA). The window ends at the
  `jmp` back to 0x605e8ae at 0x605e8e5; the `int3` padding from
  0x605e8e7 and the next function at 0x605e8f0 are excluded.
- Wrapper: 0x605e8f0..0x605e902 (18 bytes), FDE at .eh_frame offset
  0x75a32c, length 0x18, CIE 0x730230 (LSDA augmentation). The window
  ends at the `ret` at 0x605e901; the `int3` padding from 0x605e902
  and the next function at 0x605e910 are excluded.
- Callback: 0x606a890..0x606a8bf (47 bytes), FDE at .eh_frame offset
  0x368ddc, length 0x18, CIE 0 (no LSDA). The window ends at the tail
  jump at 0x606a8bd; the `int3` padding from 0x606a8bf and the next
  block at 0x606a8c0 are excluded.
- Lazy-init callee 0x605e860 is NOT re-excerpted here: it was mapped
  whole by #2244 (FDE at .eh_frame offset 0x367840, length 0x1c,
  CIE 0), and this packet takes its semantics from there.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x605e8a0 --stop-address=0x605e8e7 work/hl-node-115.bin
objdump -d --start-address=0x605e8f0 --stop-address=0x605e902 work/hl-node-115.bin
objdump -d --start-address=0x606a890 --stop-address=0x606a8bf work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. All three
windows start with `endbr64`; every mnemonic in the excerpts is
genuine objdump output from the target binary, not a placeholder, and
verify.py checks sampled instructions byte-for-byte against a fresh
objdump run and the raw binary. Instruction-level detail lives only in
the verbatim excerpts; records.json carries semantic records, not a
per-instruction list.

## Semantics (literal)

### Variant 0x605e8a0

Argument: rdi = holder object. Returns void. Fields: qword at +0x00
is the inner pointer, qword at +0x08 is the callback's second
argument, byte at +0x10 is the first flag, byte at +0x11 is the
second flag. The inner object's first qword is at +0x00 and a qword
field at +0x20 gates the callback.

```
if byte [holder + 0x10] == 0:
    lazy_init(holder)               # 0x605e860, mapped by #2244; see below
inner = [holder]                    # re-read AFTER the lazy-init call
if inner == 0:
    return                          # second flag untouched
if byte [holder + 0x11] != 0:
    return                          # second flag untouched
if [inner] != 0 or [inner + 0x20] != 0:
    callback(inner, [holder + 0x08])  # 0x606a890, mapped in this packet
byte [holder + 0x11] = 1            # set whether or not the callback ran
return
```

The lazy-init call (mapped by #2244) is, stated literally: flag
[arg + 0x10] != 0 returns at once, flag untouched; inner null returns
at once, flag untouched; otherwise its own callback 0x606a110 runs
exactly when [inner] != 0 or [inner + 0x20] != 0, then flag
[arg + 0x10] is set to 1 whether or not that callback ran. The
variant therefore never returns early on the first flag: a first-flag
value of 0 only triggers the lazy-init call, and the second-flag
logic always runs afterwards. The two flags are independent: the
first flag is owned by 0x605e860, the second flag only by this
variant.

### Callback 0x606a890

Arguments: rdi = object, rsi = amount. Returns only via the tail
jump below; it has no `ret` of its own.

```
if [object + 0x20] != 0:
    call 0x606a170(object)          # by contract only, not read
else if [object] != 0:
    lock sub amount, [object + 0x10]  # atomic 64-bit subtract
tail-jump 0x606a650(object)         # by contract only, not read
```

Every path ends in the tail jump to 0x606a650 with rdi = object:
the [object + 0x20] != 0 path skips the subtract entirely, the
[object] == 0 path skips it too, and only the ([object + 0x20] == 0
and [object] != 0) path performs it. The subtract is the only
observable store in this function.

### Wrapper 0x605e8f0

Forwards rdi unchanged to the variant (0x605e8a0) and returns. It
adjusts the stack by 8 bytes around the call and has no other effect.

### Callers

Variant callers (all real e8 calls, sites and argument setup only):

- 0x5f10d5f in 0x5f10d40..0x5f11798: rdi = caller argument + 0x80
  (lea at 0x5f10d4c, mov at 0x5f10d57, immediately before the call).
- 0x605cc5f in 0x605cc30..0x605cf73: rdi = qword at caller argument
  + 0x8e8, null-guarded (test at 0x605cc5a, je at 0x605cc5d skips
  the call when it is 0).
- 0x605e8f8 inside the wrapper 0x605e8f0..0x605e902: argument
  forwarded unchanged.

Wrapper consumers (census-confirmed):

- 0x5f10280 in 0x5f101b2..0x5f103e6: direct call, rdi restored from
  stack slot 0x30(%rsp) immediately before the call.
- 0x5f114b5 in 0x5f10d40..0x5f11798: tail jump with rdi = r12 (mov
  at 0x5f114a8); what r12 holds at that point is not pinned beyond
  that mov. Note the same containing function also calls the variant
  directly at 0x5f10d5f, so it reaches the variant by both routes.

The variant returns void, so no caller tests a return value.

## Unknowns (stated, not filled in)

- Names/meanings of the holder fields, the two flags, the inner
  object's +0x20 field, and the callback's amount argument.
- Internals of 0x606a170 and of the tail-jump target 0x606a650 (by
  contract only), and of the lazy-init's own callback 0x606a110
  (mapped by #2244 only as a call site).
- Caller internals beyond the call sites and their immediately
  preceding argument setup.
