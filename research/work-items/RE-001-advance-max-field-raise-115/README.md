# RE-001: node #115 advance-past leaf 0x5f6f400 and max-store leaf 0x5f6f430 with their seven call sites

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what do the two adjacent
small leaves at 0x5f6f400 and 0x5f6f430 do to two qword fields of one
object, and where does the binary call them? The two leaves are
modelled end to end, together with ALL seven of their direct call
sites in the binary (whole-file census) — a complete behavior, not a
lone-window fragment. The leaves take no other input, make no calls,
and touch nothing else.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` at the head of each leaf window is a genuine
instruction present in the target binary, not a placeholder.
Instruction-level detail lives only in the whole-function verbatim
excerpts in main-advance.txt and main-max.txt and the verbatim site
excerpts; the JSON in this packet holds semantic records only. The
objdump command that produced the excerpts is recorded in
export_excerpts.py, which regenerates them byte-for-byte.

## Semantics, stated literally

Both leaves take (obj, value) in (rdi, rsi) and return void. All
comparisons are unsigned 64-bit; all arithmetic wraps mod 2**64.

### Advance-past leaf 0x5f6f400 (36 bytes, FDE 0x5f6f400..0x5f6f424)

* Read current = the qword at obj + 0xd8.
* If value >= current (unsigned): store (value + 1) mod 2**64 at
  obj + 0xd8.
* Otherwise: store nothing; obj + 0xd8 is unchanged.
* Nothing else is read or written. The leaf makes no calls.

Consequences, stated literally: value == current advances the field
to current + 1 (the branch is taken on equality, not only on
strictly-greater); value = 2**64 - 1 with current <= value stores 0
(the +1 wraps); a smaller value leaves the field exactly as it was.

### Max-store leaf 0x5f6f430 (32 bytes, FDE 0x5f6f430..0x5f6f450)

* Read current = the qword at obj + 0xe0.
* If current < value (unsigned): store value at obj + 0xe0.
* Otherwise: store nothing; obj + 0xe0 is unchanged.
* Nothing else is read or written. The leaf makes no calls.

So the max leaf is exactly current = max(current, value) unsigned,
while the advance leaf is current = value + 1 (wrapping) whenever
value >= current, else unchanged. The two fields are distinct
(+0xd8 vs +0xe0) and neither leaf touches the other's field.

## Call sites (site-only)

Census (whole-file scan, reproduced by census.py and re-run inside
verify.py): advance leaf exactly 5 direct calls, 0 tail jumps,
0 stored qwords, 0 RELATIVE addends; max leaf exactly 2 direct
calls, 0 tail jumps, 0 stored qwords, 0 RELATIVE addends.

Advance leaf:

* 0x5e6987d, inside 0x5e68fd0..0x5e6b82a: rdi = the qword at
  [r14 + 0x68], rsi = rbx. After the call the caller loads its next
  argument from stack slot -0x558(%rbp).
* 0x5e6b3ac, inside the same caller 0x5e68fd0..0x5e6b82a:
  rdi = the qword at [r14 + 0x68], rsi = r12 after it is incremented
  by 1. After the call the caller loads the qword at [r14 + 0x68]
  into rax.
* 0x5e82edc, inside 0x5e82cc0..0x5e844e1: rdi = the qword at
  [r13 + 0x68], rsi = the qword at stack slot -0x320(%rbp). After
  the call the caller builds a stack address at rbp - 0xb0.
* 0x5f9dfc1, inside 0x5f9daf0..0x5f9eccd (shared caller, see below):
  rdi = the qword at [rbp + 0x60], rsi = the qword at stack slot
  0x160(%rbp). After the call the caller loads the next value and
  calls the advance leaf again.
* 0x5f9dfd1, inside the same shared caller: rdi = the qword at
  [rbp + 0x60], rsi = the qword at stack slot 0x158(%rbp). After
  the call the caller loads the qword at [rbp + 0x60] into rax.

Max leaf:

* 0x5f9846d, inside 0x5f95b80..0x5f98c8d: rdi = rbx, rsi = r13.
  After the call the caller jumps to 0x5f977ab.
* 0x5f9dfb1, inside the shared caller 0x5f9daf0..0x5f9eccd:
  rdi = the qword at [rbp + 0x60], rsi = the qword at stack slot
  0x178(%rbp). After the call the caller loads the next value and
  calls the advance leaf.

## Shared-caller sequence (observed, not a wider caller claim)

In the shared caller 0x5f9daf0..0x5f9eccd, the three calls run in
this order on the same object (the qword at [rbp + 0x60], reloaded
before each call): max-store with the 0x178(%rbp) value, then
advance-past with the 0x160(%rbp) value, then advance-past with
the 0x158(%rbp) value. The combined effect on that object is
exactly the three leaf rules applied in that order: +0xe0 becomes
max(+0xe0, value178), then +0xd8 advances past value160, then
+0xd8 advances past value158. The caller's wider behavior,
including its preceding call to 0x5d8d0d0, is not claimed.

## Not claimed

Caller semantics beyond the site arguments and post-call steps; any
meaning for the +0xd8 or +0xe0 fields beyond the two update rules,
or for the values passed at the call sites; any relation between
the two leaves beyond their shared caller sequence above; the
contents of the objects at [r14 + 0x68], [r13 + 0x68] or
[rbp + 0x60] beyond the field offsets read and written. This item
is distinct from open PR #2248 (tracker watermark pair), which pins
a max store at a different field (+0x80) on different functions;
no address or field in this item overlaps it.
