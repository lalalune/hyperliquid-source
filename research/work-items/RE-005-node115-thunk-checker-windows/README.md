# RE-005 node 115 — dispatcher thunk mechanism and the two checker_a call windows

This packet answers the two questions the
remaining-edges packet (#2741) carried over, for the
authenticated hl-node 115 artifact only (105,896,032
bytes, SHA-256 `a6e2897c…5301`).

Four small bodies are exported in full (`thunk`,
`main_shim`, `trampoline`, `indirect_caller`); every
other body is extent/digest pinned in `records.json`
and `frames.txt`. Reproduce with
`tools/thunk_checker_windows_static.py`
(`--generate` regenerates; plain run verifies against
`records.json`).

## Question 1 — how the thunk 0x2cd8370 is invoked: SETTLED (program entry, once)

The mechanism is the ordinary program entry chain —
not an indirect slot in a data segment, and not an
entry registered by runtime start-up:

1. `_start` (0x1419300) passes `main` = body
   0x2cef8f0 to `__libc_start_main` (GOT slot
   0x64df458; lea at 0x1419318, call at 0x141931f).
2. The main shim 0x2cef8f0..0x2cef917 (39 bytes,
   exported) builds a stack closure whose first word
   is the thunk: `lea 0x2cd8370,%rax` at 0x2cef8f7,
   `mov %rax,(%rsp)` at 0x2cef8fe. It calls the
   runtime entry body 0x5c99970 (1,749 bytes, pinned)
   through GOT slot 0x64e6c30 (RELATIVE → 0x5c99970)
   with rdi = &closure, rsi = static table 0x6440b48,
   rdx = argc, rcx = argv, r8 = 0.
3. After runtime initialisation the entry body
   reloads the saved table pointer and calls the
   function pointer at [table+0x28] at 0x5c99e21.
   That slot (0x6440b70) resolves via RELATIVE
   relocation to the trampoline 0x292c5c0..0x292c5cd
   (13 bytes, exported; the same body also sits in
   the table's +0x20 slot, 0x6440b68).
4. The trampoline loads closure[0] — the thunk —
   into rdi (`mov (%rdi),%rdi` at 0x292c5c1) and
   calls the 5-byte indirect caller
   0x2c7bb70..0x2c7bb75 (exported), whose
   `call *%rdi` at 0x2c7bb71 invokes the thunk.

So the thunk runs **exactly once per process, on the
main thread, at start-up**. The negative space is
censused, not assumed: no direct call/jump to the
thunk or the dispatcher anywhere in .text except the
thunk's own call to the dispatcher (0x2cd83a2); no
RELATIVE addend or offset names the thunk, the
dispatcher, the shim or the indirect caller (the
two exceptions are the mechanism itself: the
runtime entry is named by its GOT slot 0x64e6c30,
and the trampoline is held by the two static-table
slots above); no
absolute qword or u32 occurrence of either address
anywhere in the file; no aligned interior word in
any section falls inside either body's extent; all
168 `.init_array` entries and the single
`.fini_array` entry (0x14193a0) resolve to other
bodies; the only rip-relative lea/mov in .text that
names the thunk is the shim's lea at 0x2cef8f7, and
none names the dispatcher, the drivers, the gates
or checker_a.

**Frequency bound.** The entry mechanism fires once,
so it imposes no rate bound of its own. How often
the drivers re-invoke the gates is decided inside
the dispatcher body (0x2ae1690, pinned): one
backward span — head 0x2ae1974, back-edge `jne` at
0x2ae21ff, taken while the body 0x5cdf300 called at
0x2ae21f7 returns non-null — encloses both driver
call sites (driver_a at 0x2ae1a47, driver_c at
0x2ae1eeb). Per dispatcher-loop iteration each
driver runs once and, per #2741, each driver calls
its gate twice.

## Question 2 — the two checker_a call windows: BOTH break zero-before-call on one edge

#2741 showed every fully traced checker_a call site
zeroes the entry byte ([instance+0x90]) immediately
before the call. The two windows it could not trace
do **not** both have that property.

**Window A — call 0x2b90b05** in body
0x2b905a0..0x2b91042 (2,722 bytes, pinned). Instance
= &[rbx+0xf0] (lea at 0x2b90af3), entry byte
[rbx+0x180], tested == 3 right after the call at
0x2b90b12. The setup block 0x2b90af3 has exactly two
inbound edges in the whole .text (direct-branch
census + this body's jump tables):

- `jmp` at 0x2b90de2 — immediately after the zero
  store `movb $0,[rbx+0x180]` at 0x2b90ddb;
- `jmp` at 0x2b9087e — **case 4 of jump table
  0x607328** (dispatched on byte [rbx+0xca], loaded
  at 0x2b90725, indirect jump at 0x2b9074d), with no
  store to the entry byte anywhere on its path.

The only store to [rbx+0x180] in the whole body is
the zero store at 0x2b90ddb (store census over the
disassembly). On the table edge the checker receives
the byte as last written — by checker_a itself (3,
on its predicate-nonzero arm) or by code outside
this body — so a nonzero entry byte is not excluded
and the checker's state-3 resume arm stays
reachable in principle through this window.

**Window B — call 0x2cc7fb5** in body
0x2cc1120..0x2cc971b (34,299 bytes, pinned). Same
shape, offsets shifted: instance = &[r15+0x240]
(lea at 0x2cc7fa6), entry byte [r15+0x2d0], tested
== 3 after the call at 0x2cc7fc6. The setup block
0x2cc7fa6 has exactly two inbound edges:

- `jmp` at 0x2cc92c6 — immediately after the zero
  store `movb $0,[r15+0x2d0]` at 0x2cc92be;
- **case 4 of jump table 0x60bdb8** (dispatched on
  byte [r15+0x1da], loaded at 0x2cc21d0, indirect
  jump at 0x2cc21f2), with no zeroing store on its
  path.

Window B's entry byte has exactly two stores in the
body (store census): the zero store at 0x2cc92be
and, at 0x2cc5125, `mov %cl,[r15+0x2d0]` — a
non-constant store in a record-duplication phase,
where cl is the byte copied from [r15+0x10d]
(loaded at 0x2cc5031). The byte is therefore
explicitly initialised from record data, not from
zero, on that phase.

## Boundaries kept open

- Whether the un-zeroed table edges are exercised
  with a nonzero entry byte at runtime is dynamic:
  statically the byte can be 3 (left by a previous
  checker_a call) or a copied value (window B), but
  which object states reach those switch cases is
  not decidable from these two bodies alone.
- The checker_a *clone* callers of the gate_a mirror
  family (censused in #2741's records) were not
  re-traced; their zero-before-call status stays as
  #2741 left it.
- The dispatcher loop's tail callee 0x5cdf300 is
  identified only as the body whose non-null return
  keeps the loop running (it sits in the TLS
  accessor cluster next to the destructor 0x5cdf410
  of #2741); its own body is not traced here.
