# RE-005 node115: the 31 sibling vtables that share the io-error Debug stub

## Question

The error-vtable packet (PR #3043) pinned the one-method vtable
at 0x64005f0 — {drop = 0x15be1a0, size 8, align 8, method = the
PLT stub 0x5ca5610 resolving to the Debug format function
0x5ca7ea0 of the 8-byte tagged std io error value} — and
recorded as its closing boundary that 32 vtables in .data.rel.ro
name the same stub at +0x18, plus one .got cell (0x64e0170).
What are the other 31 vtables vtables *of*? For each one: its
drop body, its size/align, its full slot layout, and the bodies
that produce or consume the value it tags.

## Findings

**All 31 siblings are vtables for the same value: the 8-byte
tagged std io error.** No sibling belongs to a different value.
Every one of the 32 headers reads size 8 / align 8. Between them
they name 30 distinct drop bodies (two pairs of vtables share a
drop: 0x645b248/0x645b320 share 0x2e854e0, 0x649db98/0x649e030
share 0x4e509c0), and every drop is the same tag-dispatch
template the first packet pinned for 0x15be1a0: load the stored
word, mask tag & 3; tags 0, 2 and 3 do nothing; tag 1 untags the
pointer to the 0x18-byte custom-error box, drops the inner error
through the inner value's own vtable, and frees the box and the
inner allocation through the shared dealloc slot 0x64df4a0. 28
drops are 209 bytes; 0x15dd590 is a 173-byte variant whose
landing pad delegates to a cleanup helper, and 0x5c74b90 a
206-byte frame variant — the dispatch, the box layout and the
dealloc calls are identical. Each drop is a local instantiation
of the value's drop glue, which is why the same value carries 30
of them.

**Three structural families.** 18 vtables (0x64005f0 among them)
are standalone: extent 0x20, the header plus the one Debug stub
slot. 13 are extended vtables of extent 0x58 whose eight method
slots follow one recurring shape:

- +0x18 — the shared Debug stub 0x5ca5610;
- +0x20 — 0x5ca84b0, the value's Display format function. The
  identification is byte-pinned, not guessed: the body
  references the string fragment "(os error " at 0x43d45f and
  "strerror_r failure" at 0x949f1e, and dispatches on the same
  tag through the jump table at 0x948ca0, beside the Debug
  body's table at 0x948c90;
- +0x28 — a pointer to the one-method Display vtable at
  base−0x20, a sibling header with the same drop, size 8,
  align 8 and 0x5ca84b0 as its only method;
- +0x30 — the forwarder 0x5ca8760 (41 bytes): on tag 1 it calls
  the boxed error's own vtable +0x30 slot and returns the
  result; on every other tag it returns 0;
- +0x38, +0x40, +0x50 — local bodies, recorded as targets in
  records.json and not further identified;
- +0x48 — the forwarder 0x5ca8730 (41 bytes), the same shape
  forwarding to the boxed error's +0x48 slot.

One sibling is an outlier: tokio's 0x64c6458 (extent 0x40),
whose four extra slots (0x5cee570, 0x5cee590, 0x5cee5a0,
0x5cee5c0) are local bodies in the tokio address range — among
them refcount-style shims that adjust the data pointer by
−0x80. Its Self is still the 8-byte io error by drop
(0x5cee460, the template above), size, align and the Debug
slot; which trait the four slots serve is not identified here.

**References: 94, all rip-relative lea.** A binary-wide census
in the style of the earlier packets (rip-relative scan of
.text, movabs scan, relocation-addend scan, raw-qword scan of
the allocated data sections) finds no other reference form for
any of the 32 vtables. The 94 sites classify by the shape of
the referencing body:

- 57 panic-pair sites: the body stores an error value on the
  stack and calls the panic thunk 0x1680c30 through slot
  0x64df6a0 with (message, value pointer, this vtable,
  Location) — the same shape the first packet pinned for
  0x64005f0. Message and Location are extracted and pinned per
  site in records.json. The census includes 13 "failed to
  spawn thread" expects (12 at thread/functions.rs:131 spread
  over seven vtables, one more in the node's base/src/lu.rs),
  tokio's seven "failed to wake I/O driver"
  sites (runtime/io/driver.rs:272) on 0x64c6458, the node's own
  sources (base/src/ren.rs:234 "ren restart file error",
  base/src/lu.rs:55/58 "tokio_run" and lu.rs:159, base/src/
  log/handle.rs:136, node/src/utils.rs:66, global_constants/
  src/aws_name.rs:295), both vendored copies of hyper's
  "&mut [u8].write() cannot error" (proto/h1/encode.rs:324) on
  two different vtables, and 27 libstd-internal unwrap sites
  on libstd's own vtable 0x64c3270 (sys/pal/unix/time.rs:101/
  103, sys/process/mod.rs:57/61/65, sys/random/linux.rs:136/
  157).
- 6 field accessors: a 12-byte body — `lea 0x38(%rdi), %rax;
  lea <vtable>, %rdx; ret` — returning the parent trait
  object's field at +0x38 paired with one of these vtables.
  Each accessor is itself a method entry of a larger parent
  vtable; records.json pins the parent vtable, the entry
  offset, and the parent's Self size and drop.
- 10 enum accessors: a small body that discriminates an enum
  by its niche tag (comparisons against 0x8000000000000001/2)
  and returns one arm's field at +8 paired with one of these
  vtables (the other arm pairs a different vtable, e.g.
  0x640d6f0 beside 0x640d678).
- 14 pair-store sites and 3 clone sites: bodies that write a
  fresh (value, vtable) pair into a box or object under
  construction, or return such a pair in registers.
- 4 other sites: one passes the vtable in r8 as an argument to
  an indirect call (body 0x16087a0, vtable 0x64032c8); three
  hold it in r13 inside body 0x17457f0 while assembling a
  larger value (vtable 0x640e4e0).

## Boundaries

The parent traits of the accessor, store and clone bodies are
recorded structurally (parent vtable base, entry offset, Self
size and drop) but never named: the byte evidence pins the
layout, not trait names. The extended vtables' local slots
(+0x38, +0x40, +0x50) and tokio vtable 0x64c6458's four local
slots are recorded as targets; the traits they serve are not
identified. The two forwarders are pinned by their forwarding
targets inside the boxed error's vtable (+0x30 and +0x48);
their trait-slot names are not asserted. Panic messages and
Locations are read from the static records the bodies load;
no value was executed.

## Reproduce

Materialize the artifact (customary pointer-file restore),
then:

```
python3 tools/shared_debug_vtables.py generate
python3 tools/shared_debug_vtables.py check
python3 -m unittest tests.test_shared_debug_vtables
```
