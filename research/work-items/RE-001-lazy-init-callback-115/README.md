# RE-001: map node #115 lazy-init callback 0x606a110 with its lazy-init caller and consumers

## Bounded question

The lazy-init mapped by #2244 (0x605e860) ends in a call to 0x606a110
that #2244 left by contract only, and #2259's packet lists that
callee as an open unknown. What does the callback itself do, and how
does it complete the lazy-init behavior end to end — from the
holder's flag gate, through the callback's own null check and store,
to the flag set — and who are the lazy-init's two census-confirmed
consumers? This packet pins the whole behavior end to end, not a
lone-window fragment: the 62-byte lazy-init whole, the 22-byte
callback whole, and both lazy-init call sites (the sibling drain
driver and the two-flag variant).

## Windows

- Lazy-init: 0x605e860..0x605e89e (62 bytes), FDE at .eh_frame offset
  0x367840, length 0x1c, CIE 0 (no LSDA). The window ends at the
  `ret` at 0x605e89d; the `int3` padding from 0x605e89e and the next
  function at 0x605e8a0 are excluded.
- Callback: 0x606a110..0x606a126 (22 bytes), FDE at .eh_frame offset
  0x368dc8, length 0x10, CIE 0 (no LSDA). The window ends at the
  `ret` at 0x606a125; the next block at 0x606a126 belongs to a
  different function (a mutex-unlock/unwind sequence, not read here)
  and is excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x605e860 --stop-address=0x605e89e work/hl-node-115.bin
objdump -d --start-address=0x606a110 --stop-address=0x606a126 work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. Both
windows start with `endbr64`; every mnemonic in the excerpts is
genuine objdump output from the target binary, not a placeholder, and
verify.py checks sampled instructions byte-for-byte against a fresh
objdump run and the raw binary. Instruction-level detail lives only in
the verbatim excerpts; records.json carries semantic records, not a
per-instruction list.

## Semantics (literal)

### Lazy-init 0x605e860

Argument: rdi = holder object. Returns void. Fields: qword at +0x00
is the inner pointer, qword at +0x08 is the callback's second
argument, byte at +0x10 is the flag. The inner object's first qword
is at +0x00 and a qword field at +0x20 gates the callback.

```
inner = [holder]
if inner == 0:
    return                          # flag untouched
if byte [holder + 0x10] != 0:
    return                          # flag untouched
if [inner] != 0 or [inner + 0x20] != 0:
    callback(inner, [holder + 0x08])  # 0x606a110, mapped in this packet
byte [holder + 0x10] = 1            # set whether or not the callback ran
return
```

### Callback 0x606a110

Arguments: rdi = inner object, rsi = amount. Returns void.

```
if [inner] == 0:
    return                          # no store
lock sub amount, [inner + 0x18]     # atomic 64-bit subtract, wrapping
return
```

The callback re-reads [inner], the same field the lazy-init tested,
so its null arm is reachable exactly through the lazy-init's
[inner + 0x20] != 0 arm: when [inner] == 0 but [inner + 0x20] != 0,
the lazy-init calls the callback and the callback returns without
storing. The subtract at +0x18 is the callback's only store, and the
lazy-init's flag set at +0x10 is the lazy-init's only store.

### Consumers of the lazy-init

Both return-void call sites, sites and argument setup only (the
containing functions are mapped by #2244 and #2259 respectively;
their internals are not re-read here):

- 0x5f14117 in the sibling drain driver 0x5f140c0..0x5f14179
  (mapped by #2244): rdi = holder at caller + 0x80 (lea at
  0x5f14110, immediately before the call).
- 0x605e8e0 in the two-flag variant 0x605e8a0..0x605e8e7 (mapped by
  #2259): the variant's own holder argument, unchanged; the call
  runs only when the variant's first flag is 0, and the variant's
  second-flag logic always runs afterwards.

## Unknowns (stated, not filled in)

- Names/meanings of the holder fields, the flag, the inner object's
  +0x18/+0x20 fields, and the callback's amount argument.
- Caller internals beyond the call sites and their immediately
  preceding argument setup.
