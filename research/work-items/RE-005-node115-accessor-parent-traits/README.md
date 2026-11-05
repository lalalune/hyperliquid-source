# RE-005 node115: the parents of the shared-Debug census's accessor, store and clone bodies

## Question

The shared-Debug-vtable packet (PR #3141) catalogued the 32
vtables of the 8-byte tagged std io error value and closed with a
reference census it did not resolve: 33 further reference sites
whose bodies consume the same (data, vtable) pair shape —
6 field accessors, 10 enum accessors, 14 pair-stores and
3 pair-clones. Those sites' bodies were recorded structurally
only; which parent trait or concrete type each body serves was
left open. This packet answers that, body by body, and marks
what the binary cannot answer.

## Findings

### The shared parent layout is std::error::Error

Every vtable that owns one of the census's accessor bodies has
the same first six method slots (after the drop/size/align
header), the layout this toolchain (rustc
59807616e1fa2540724bfbac14d7976d7e4a3860) emits for
`dyn std::error::Error`:

| slot | role | how it is pinned |
| --- | --- | --- |
| +0x18 | Debug::fmt | body identity per type (below) |
| +0x20 | Display::fmt | body identity per type (below) |
| +0x28 | upcast cell → the Display-only sibling vtable at base−0x20 | holds in all 11 parents |
| +0x30 | `source()` | returns (data, vtable) pairs or None — the census's "pair-returning accessors" |
| +0x38 | hidden `type_id` | 14-byte body writes a 16-byte constant through the out pointer; the constant is equal for every vtable of one concrete type and differs across types (two families measured) |
| +0x40 | deprecated `description()` | every parent uses the default body returning the (ptr, 40) pair for "description() is deprecated; use Display" |
| +0x48 | deprecated `cause()` | a second body with the same arm logic as `source()` (for openssl::ssl::Error, twin 52-byte instantiations) |
| +0x50 | `provide()` | the default no-op (1-byte ret) in every parent |

So the census's ten "enum accessor" sites are the `source()`
(+0x30) and `cause()` (+0x48) slots of five Error vtables, and
its six "field accessor" sites are one slot inside six further
Error-family vtables (next sections).

### The five enum-accessor parents are two concrete error types

Both types wrap the same tagged word: word
0x8000000000000000 → the value at +8 is an io error (returned
with the extended io vtable 0x63f8f58); word
0x8000000000000001 → None; a small/pointer word → the value at
+0 is an ErrorStack (vtable 0x63f8fd0, itself pinned here as a
leaf error: its source/cause slots are the shared 3-byte None
body 0x14c5840, its Debug writes "ErrorStack(", its Display
writes "OpenSSL error" / ", ").

- **openssl::ssl::Error** (32-byte Self; vtables 0x63f9150 and
  0x64c7438). Debug bodies 0x14cafa0 / 0x5d01740 write the
  struct name "Error" with fields "code" (an ErrorCode at +0x18,
  formatted as "ErrorCode(") and "cause" (the tagged word at
  +0); Display is the shared openssl error Display body
  0x5badac0; the drops free the ErrorStack Vec at +0 or
  tail-drop the io error at +8 by the same tag word.
- **The vendored native-tls OpenSSL backend's error enum**
  (40-byte Self; vtables 0x63f9240, 0x640e648, 0x644e7f8, all
  sharing Debug body 0x475bee0 and Display body 0x475c850).
  The Debug body dispatches through a 4-entry jump table and
  writes the variant names, in declaration order: Normal
  (formats the ErrorStack at +8), Ssl (formats the value at
  +0x20), EmptyChain, NotPkcs8 (write_str only). The Display
  body writes "at least one certificate must be provided to
  create an identity" and "expected PKCS#8 PEM" and delegates
  to the ErrorStack Display text. Neighbouring bodies panic in
  z_vendor/native-tls/src/imp/openssl.rs (line 90) and, for the
  0x640e648 instance, z_vendor/tokio-native-tls/src/lib.rs
  (line 124).

### The six field-accessor parents are one Error-subtrait

Each of the six vtables (0x6444b60, 0x64845c0, 0x6494f80,
0x6496a80, 0x649e3f0, 0x63fa140; Self sizes 64/80/72/72/64/64)
is the dyn vtable of one concrete type implementing a single
trait that extends Error: the Error vtable above forms the
prefix, one own method follows at +0x58, and the rest of the
vtable is K identical six-method groups (K = 8, 4, 2, 4, 7, 15
respectively — the extent is always 0x58 + K·0x30). In each
group, in slot order:

1. a field accessor returning a sub-object as a trait object
   (the census's field accessors are the instances of this slot
   whose per-group vtable is the extended io vtable: they
   return (self+0x38, 0x63f8f58) — all six types store the same
   io::Error field at +0x38),
2. a pair return (self, per-group sibling vtable),
3. a 33-byte keyed lookup: byte-compare a 16-byte key against
   a per-group constant; return self+0x38 on equality, null
   otherwise,
4. a 72–141-byte worker body (drop glue: conditional inner
   drop, then free through the shared dealloc slot),
5. a 3-byte body returning 0,
6. a second worker body of the same glue shape.

The Debug/Display slots of these vtables are delegation shims
(load Self's first word, call through [word+8], then
tail-dispatch on the third argument's vtable): the wrappers
forward their Error formatting to an inner object. Xrefs place
the family in the vendored HTTP/TLS client stack: the
pair-store body 0x2e7db50 (panic Locations in socket2 and the
hyper-fork HTTP connect code) and the pair-store body
0x2e86150 both construct the 0x6444b60 trait object, and the
sibling vtable 0x6444980 (same shim prefix, 80-byte Self) is
constructed in a body whose panic Location is
z_vendor/tokio-openssl/src/lib.rs:752.

### The store and clone bodies

The seven pair-store bodies are large functions (234–3229
bytes). At each census site the stored pair is produced in
rax:rdx and written with one 16-byte MOVAPS store; in six of
the seven bodies the surrounding stream also frees a previous
pair's contents through the shared dealloc slot — i.e. these
are assignment sites that replace a held error trait object
(the seventh site, in body 0x2ccaaf0, has no such cleanup in
the pinned window). Two of the bodies (0x2e7db50, 0x2e86150)
additionally construct field-parent trait objects (above).
The three pair-clone bodies (215–224 bytes) take the
destination pair slot and the source pair among their first
arguments and produce a fresh (data, vtable) pair, consumed
in rax:rdx at each census call site — the clone path of the
same held-error representation.

## Boundary

- The Error-subtrait behind the six field-accessor parents is
  not named anywhere in the binary: no string or panic
  Location names it, and its method bodies are generic glue.
  Its layout, group structure and construction neighbourhood
  are pinned; its source-level name is not recoverable.
- For the native-tls enum parents, which named variant owns
  the small-word source() arm is not asserted: the Debug jump
  table maps the small-word arm to Ssl (formatting +0x20)
  while the accessor returns the word at +0 as an ErrorStack.
  The observed word→pair mapping itself is pinned.
- The pair-store/pair-clone bodies carry no panic Location of
  their own except 0x2e7db50; their shapes and xref facts are
  pinned, their source-level identities are not.
- Three slot bodies are shared between the io vtables of
  PR #3141 and these parents (the +0x38 TypeId writer
  0x14c5950, the +0x40 description body 0x14c5750, the +0x50
  provide body 0x14c58a0). They appear here only as slot-role
  evidence for the parents; the io-vtable census itself is
  PR #3141's subject and is not re-claimed.

## Method

All vtables were re-derived from the materialised binary
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301)
by applying .rela.dyn RELATIVE relocations and scanning
.data.rel.ro for drop/size/align headers whose drop is an FDE
body — the same machinery as the census packet.
`tools/accessor_parents.py generate` rebuilds records.json
from the binary and `check` verifies the retained copy; the
generator asserts the sibling rule, the description string,
the type-id body shapes and per-type constancy, the field
accessor shape and the group stride for every parent it
records. `tests/test_accessor_parents.py` re-runs the full
analysis and compares it against the retained records.
frames.txt indexes the disassembly excerpts in this directory.
