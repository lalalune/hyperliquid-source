# RE-005 node115: the extended io-error vtables' local slots — type_id, description, provide

## Question

The shared-Debug-vtables packet (PR #3141) pinned the 13
extended vtables of extent 0x58 for the 8-byte tagged std io
error value and recorded their full slot layout, but closed
with two explicit boundaries: the local bodies at +0x38, +0x40
and +0x50 were "recorded as targets; the traits they serve are
not identified", and the two forwarders at +0x30 (0x5ca8760)
and +0x48 (0x5ca8730) were pinned only by their forwarding
targets inside the boxed error's vtable — "their trait-slot
names are not asserted". Which trait, and which of its
methods, do these five slots serve?

## Findings

**The 11 entries are the value's vtable for
`core::error::Error`.** Header (drop / size 8 / align 8, pinned
by the preceding packets), then:

- +0x18 — Debug::fmt, the shared stub 0x5ca5610;
- +0x20 — Display::fmt, 0x5ca84b0;
- +0x28 — a pointer to the one-method Display vtable at
  base−0x20: the Display supertrait upcast entry. No second
  upcast pointer (for Debug) exists in this layout;
- +0x30, +0x38, +0x40, +0x48, +0x50 — the trait's own five
  methods, in the trait's declaration order: **source,
  type_id, description, cause, provide**. The three local
  slots identify as follows.

**+0x38 is `Error::type_id`.** Each of the 13 bodies is the
same 14-byte shim — `mov rax,rdi; movups xmm0,[rip+const];
movups [rdi],xmm0; ret` — copying a 16-byte constant into the
caller's out slot and returning the slot pointer (the sret
shape of a 16-byte by-value return). All 13 shims copy the
*same* constant from the *same* address 0x451540:
`f8dfacffdf56f26d91c0b01aa4986406`. One constant for 13
vtables of one Self is the value's TypeId; the shims differ
per crate cluster only in their own addresses.

**+0x40 is `Error::description`.** Each of the 13 bodies is
`lea rax,[rip+str]; mov edx,40; ret` — a &str return. The 13
string addresses differ (per-crate copies) but the 40 bytes
are identical everywhere and read exactly
`description() is deprecated; use Display` — the deprecated
default body text of `Error::description`, which this value
does not override.

**+0x50 is `Error::provide`.** Each of the 13 bodies is a
single `ret` (FDE extent 1). `provide` is the trait's only
unit-returning method; this value implements it as the
default no-op.

**+0x30 is `Error::source`, +0x48 is `Error::cause`.** Both
libstd forwarders are Option-shaped by construction: they
zero rax on entry and return it on every non-custom tag, and
on tag 1 (the boxed custom error) they tail-call the boxed
error's own vtable at *the same offset* and return its
result. That excludes `provide` for either slot despite the
superficial delegation shape — a unit-returning forwarder has
no result register to zero. The order between them is pinned
two ways:

1. The other own-method positions already fall in the
   trait's declaration order (type_id at +0x38, description
   at +0x40, provide at +0x50); source precedes cause in
   that order, and cause is the deprecated legacy alias of
   source.
2. A wrapper discriminator: vtable 0x644eb40 (a 32-byte
   Self) shares one body, 0x26c67b0, between its +0x30 and
   +0x48 entries. The body loads a field pointer at +0x18,
   tests its first dword against 1, then runs the io value's
   tag dispatch *inlined* and finishes with
   `call *0x30(%rax)` on the innermost error's vtable — no
   `call *0x48(%rax)` occurs in the body. That is a
   hand-written source delegating into the value's source,
   with cause reusing the body (the default cause is
   `self.source()`). Under the swapped reading the wrapper
   would have to hand-write a delegating *cause* while its
   source entry shares that body instead of carrying the
   None default — and the io value's own inlined body in it
   delegates via +0x30, matching the +0x30 forwarder
   0x5ca8760 byte for byte in shape, not the +0x48 one.

**Cross-check census.** The same 11-entry shape recurs
across the binary. Scanning for type_id-pattern shims
referenced from a relocation slot, taking candidate bases at
slot−0x38 and requiring a sane header (drop with an FDE,
size/align in range, +0x28 naming base−0x20) yields 108
vtables of other Self types on this exact layout. Among
them, 29 return None from both Option slots
(`xor eax,eax; ret` bodies) and 13 share one body between
+0x30 and +0x48 (the wrapper above among them) — the shape
is the binary's general `dyn Error` layout, not an
io-specific one.

## Boundaries

Trait names rest on the method-set fingerprint of
`core::error::Error` — the closed set {source, type_id,
description, cause, provide} over Debug + Display — plus the
pinned deprecated-default string and the shared TypeId
constant; the artifact carries no DWARF names. The Self
attribution (std::io::Error) is inherited from the preceding
packets' pins (the tag-dispatch drop template, the Display
body's "(os error " and "strerror_r failure" references),
not re-derived here. The TypeId constant is
compilation-specific; it is this value's TypeId because the
+0x38 entry of the value's own vtables returns it. Panic
messages, Locations and execution play no part: no value was
executed, and all identifications are static byte evidence.

## Reproduce

Materialize the artifact (customary pointer-file restore),
then:

```
python3 tools/extended_error_slots.py generate
python3 tools/extended_error_slots.py check
python3 -m unittest tests.test_extended_error_slots
```
