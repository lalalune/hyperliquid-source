# RE-001: map node #94 WAL reader constructor 0x51632f0

- Component ID: RE-001 (#94 function map), WAL log reader
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json; local copy `work/hl-node-94.bin`, hash verified to match)
- Source commit / reference commit: upstream main `e5c9b643` at submission time
- Claim status: observation for every field write, call shape and caller
  argument below; inference for the names of the +0x28 flag byte, the
  +0x68 log number and the +0x20/+0x18 values (all flagged in
  records.json as not pinned types, with the branch conditions pinned
  regardless)
- Scope included and excluded: the whole 238-byte window 0x51632f0..0x51633de
  (vtable install, source-pair copy, refcount increment, taken-slot move,
  0x8000-byte buffer allocation, empty-string field, all zeroed fields),
  its exception-cleanup stub 0x51632cc..0x51632eb, its vtable entries from
  the relocations, and all 7 direct callers with their r8/r9 arguments.
  Excluded, callee-only: the destructor 0x5162ed0, the logical reader
  0x51618e0 (PR #1860) and the physical-record decode 0x5161400 (PR #1848),
  whose field uses cross-check this constructor's layout; their internals
  are not re-pinned here.

## Bounded question

How does node #94 construct the WAL reader object that the logical reader
(PR #1860) and the physical-record decode (PR #1848) then operate on:
which fields are copied, moved, allocated or zeroed, how the shared
source object is refcounted, and what each of the 7 callers passes?

## Reproduce

From the repository root, with the digest-verified binary at
`work/hl-node-94.bin`:

```
objdump -d --start-address=0x51632f0 --stop-address=0x51633de work/hl-node-94.bin
python3 research/work-items/RE-001-wal-reader-ctor-94/export_excerpts.py
python3 research/work-items/RE-001-wal-reader-ctor-94/verify.py
python3 -m pytest tests/test_wal_reader_ctor.py -q
```

Note: `endbr64` and the other instruction mnemonics in the excerpt files
are genuine instructions present in the target binary, not placeholders.
Instruction-level detail lives only in those verbatim excerpts; the JSON
in this packet holds semantic records, never a per-instruction list.
The objdump header spells the binary path exactly as given, so the
excerpts must be regenerated from the repository root with the relative
path, as `export_excerpts.py` does.

## Evidence

Window: FDE `0x006354a4 pc=00000000051632f0..0x51633de`, 238 bytes,
no canary (only rbp/rbx pushed, 8-byte stack adjustment). Arguments:
out in rdi, source pair in rsi, taken-slot pointer in rdx, verbatim
value in rcx, flag byte in r8's low byte, log number in r9.

Construction, in order: the vtable pointer 0x575b0b8 is stored at +0x00;
the source pair's first qword goes to +0x08 and its second qword to
+0x10; when the second qword is nonzero, its +0x08 refcount field is
increased by 1 — with a plain add when the global byte at 0x5777ed8 is
nonzero, and with a lock-add when it is zero (both forms are in the
window, at 0x5163335 and 0x51633c8); the taken slot's first qword is
moved to +0x18 and the slot is cleared to 0; rcx goes verbatim to +0x20;
the r8 low byte goes to +0x28; operator new[] allocates 0x8000 bytes
into +0x30; +0x38 is set to the rodata pointer 0x1e629b (first byte NUL,
followed by an h2 crate path string) with +0x40 = 0, i.e. an empty slice;
+0x48 is a zero u16; +0x50/+0x58, +0x60, +0x78/+0x80 and +0xa8/+0xb0 are
zeroed; +0x68 is r9; +0x70 is a zero u32; and +0x88/+0x90/+0x98 is an
empty string (pointer = the object's own +0x98 inline buffer, size 0,
first buffer byte 0).

Vtable (from the R_X86_64_RELATIVE relocations; the file bytes at these
.data.rel.ro slots read zero in this capture, so the relocation addends
are the installed values): the first virtual function is the destructor
0x5162ed0, the second is the logical reader 0x51618e0 — so this object
is the polymorphic reader whose destructor and read routine are already
mapped, not a plain data struct.

Callers (census: full executable-segment e8 scan; no tail jumps, no
qword reference to the constructor itself): exactly 7 direct callers.
Six pass r8 = 1; the seventh (0x52136b9) passes a zero-extended byte
from its own struct +0x18. r9 is 0 at three callers, rbx at two, and a
caller-stack value at the replay caller (0x520b49e) and at 0x52136b9.
The replay caller is the loop that then calls the logical reader with
mode 0 (PR #1860), so this constructor is the setup step for WAL replay.

Field cross-checks: the destructor frees the +0x30 buffer, releases the
+0x10 refcounted object and destroys the +0x78, +0x88 and +0xa8 fields;
the logical reader reads +0x40, +0x58, +0x60, +0x68, +0x70, +0x78 and
+0xa8; the physical decode reads +0x28 (its CRC gate), +0x30, +0x38/+0x40,
+0x48/+0x49, +0x50, +0x60, +0x68 (its recyclable log-number gate) and
+0x70. Every field those consumers read is initialized by this window.

Cleanup: if the 0x8000-byte allocation throws, the landing pad at
0x51633d2 jumps to the stub 0x51632cc, which destroys the partially
constructed +0x18 field (call 0x50badf0), releases the +0x10 refcounted
object when nonzero (call 0x4f94a90), and rethrows via _Unwind_Resume.
The LSDA mapping is not claimed.

## Implementation and comparison

`tools/wal_reader_ctor.py` implements the window over caller-supplied
values (the buffer is a fresh 0x8000-byte object, the string is the
empty inline form, the refcount increment records which of the two
forms the global flag selects). No Rust component is claimed: this VM
has no cargo/rustc, so the model layer is Python, as in the reference
contributor PRs. `tests/test_wal_reader_ctor.py` pins the behavior end
to end: every field write, the null and nonzero refcount arms with both
increment forms, the taken-slot move-and-clear, the buffer size and
freshness, the empty-string form, the caller r8/r9 table, and the
packet itself (verify script, byte-for-byte sampled instructions
against a fresh objdump run and the raw binary, and a corruption
control that fails verification when an excerpt is tampered with).

## Results and limitations

- Checker: `verify.py` reports ALL CHECKS PASSED (excerpts match a
  fresh objdump run, records.json parses with its required keys, the
  four sampled instructions match the binary byte-for-byte).
- Tests: all tests in `tests/test_wal_reader_ctor.py` pass.
- Not claimed: the types of the +0x08/+0x10 source pair, the +0x18
  taken value and the +0x20 rcx value; the unwritten padding bytes
  (+0x44..+0x47, +0x4a..+0x4f, +0x74..+0x77, +0x99..+0xa7); the
  internals of the destructor beyond the field cross-checks; and the
  LSDA mapping of the landing pad.
- No gate is requested here; the packet documents one bounded work
  item for review.
- Next question: the replay loop 0x520ad30 itself (the 0x520b49e
  caller's enclosing function), which drives this constructor and the
  logical reader — its record-type dispatch is the natural follow-up,
  but at 4899 bytes it needs its own phased analysis, not a single
  follow-on claim.
