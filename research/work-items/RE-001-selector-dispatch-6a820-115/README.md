# RE-001: node #115 selector dispatch 0x5f6a820

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the 908-byte function
at 0x5f6a820 — the dispatch the index selector 0x5f6c2a0 tail-jumps to,
left unmodelled by the RE-001 later-group predicate, selector-inversion
wrapper and ingest-behind-check items — compute for one level-files
brief and one user-key range, end to end: its two arms, the exact
comparison sequence of each, its two compare routes, and the contracts
of the key builder and index finder it calls on one arm?

## Windows

* Dispatch 0x5f6a820..0x5f6abac (908 bytes, FDE range as shown in
  frames.txt). The main window of this item.
* Builder 0x5eaa060..0x5eaa10b (171 bytes). The key builder the find
  arm calls once. Read in full because the find arm's observable
  behaviour depends on the exact bytes it produces; it has 59 direct
  call sites file-wide and is claimed here only for this item's call.
* Find 0x5f69d00..0x5f69d31 (49 bytes). The index finder the find arm
  calls once. Read in full; its ordering callee 0x5f64630 is not read
  and stays an oracle (see Unknowns).
* Thunk 0x5d48410..0x5d48428 (24 bytes). The compare adapter whose
  address is the fast-route guard value. Referenced in full because
  the guard is meaningless without it; the dispatch never calls it.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The RE-002 vendor census registers this window as
`node115-vendor-5f6a820` (librocksdb-sys 0.11.0+8.1.1,
`rocksdb::SomeFileOverlapsRange(const InternalKeyComparator&, bool,
const LevelFilesBrief*, const Slice*, const Slice*)`, byte-windows
start 100050976 end 100051884, body sha256 in records.json). That
registration is an identity only; this item pins the semantics on top
of it, following the coexistence precedent of the RE-001 items for
0x605d7b0, 0x5f07200 and 0x5f0b5e0. The registered signature's argument
order matches the order read here: comparator, flag, brief,
range-start slice pointer, range-end slice pointer.

## Semantics, stated literally

Registers at entry: rdi is a comparator holder whose +8 field is
loaded once into r12 and used as the comparator object by every arm;
esi is the arm flag; rdx is the brief (count qword at +0, file-array
pointer at +8, 80-byte entries); rcx points to the range-start slice
or is null; r8 points to the range-end slice or is null. A slice is a
(data, length) pair. Each file entry carries two keys as (data, size)
pairs — key A at entry+0x30/+0x38 and key B at entry+0x40/+0x48 — and
every comparison uses the derived user slice (data, size − 8) with
wrapping 64-bit subtraction. The return value is 1 when some file
overlaps the range and 0 when none does, with one stated exception on
the find arm.

Every comparison takes one of two routes, chosen per call. When the
comparator's vtable slot +0xd0 equals the guard value 0x5d48410 — the
adapter thunk window above, which itself tail-calls
[[x+0x20]+0x10] with (x+0x20, second, fourth, x+0x20) — the fast route
calls [[r12+0x20]+0x10] with (rdi = r12+0x20, rsi = first slice,
rdx = second slice); rcx is not set by the dispatch on this route.
Otherwise the slow route calls the slot value itself with
(rdi = r12, rsi = first slice, rdx = 1, rcx = second slice, r8d = 1).
Both routes' eax is the comparison result; only its sign and zeroness
are consumed. The scan arms load the guard as the immediate
0x5d48410; the find arm's second phase loads it from the relocated
global at 0x64ecfb0 (R_X86_64_RELATIVE, addend 0x5d48410).

Scan arm (flag == 0):

```
if [brief+0] == 0: return 0
if range start is null: goto null-start arm
i = 0
loop:
  e = [brief+8] + i*80              # base and count re-read per iteration
  if compare(range start, key B of e) <= 0:
      if range end is null: return 1
      if compare(range end, key A of e) >= 0: return 1
  i += 1
  if i < [brief+0]: goto loop
  return 0
```

Null-start arm (flag == 0, count > 0, range start null): a null range
end returns 1 at once; otherwise the files are scanned in order and
the first file with compare(range end, key A) >= 0 returns 1;
exhausting the array returns 0.

Find arm (flag != 0):

```
if range start is null:
    index = 0                       # builder and find do not run
else:
    record = {range-start.data, range-start.length,
              packed = -8, tag = byte 0x16 from rodata 0x9702ab}
    s = builder(record)             # std::string, contract below
    index = find(holder, brief, &(s.data, s.size)) at 32 bits
    dispose(s)
if index >= [brief+0] (unsigned): return 0
if range end is null: return flag   # the esi value itself
e = [brief+8] + index*80
return 1 if compare(range end, key A of e) >= 0 else 0
                                # computed as (not result) >> 31
```

The builder (0x5eaa060) takes (std::string out, record) and appends
record.data[0..record.length) and then the 8 little-endian bytes of
(record.packed << 8) | record.tag to the string; each append throws
the native length error when the length exceeds
0x3fffffffffffffff minus the current size. With this item's record,
the built string is exactly the range-start bytes followed by the 8
bytes 16 f8 ff ff ff ff ff ff.

The finder (0x5f69d00) takes (comparator holder, brief, key slice
pointer), reads the brief count as a 32-bit dword, calls 0x5f64630
with (files begin, files begin + count*80, holder, key slice pointer)
and converts the returned pointer to an index by (ptr − begin) sar 4
followed by a multiply by 0xcccccccd — exact for array offsets,
because entries are 80 = 16·5 bytes and 5 · 0xcccccccd ≡ 1
(mod 2³²). What 0x5f64630 compares to order the array is not read
here; the model takes the finder's returned index as an oracle input.

Exception path (LSDA in frames.txt): while the built string is alive
(the builder and find calls), an exception lands at 0x5f6aba0, which
moves the exception pointer to rbx and jumps to the shared cleanup
tail at 0x5f6a7f7; that tail disposes the string at [rsp+8],
re-checks the stack canary and calls _Unwind_Resume. The remaining
compare calls have no landing pad — no string is alive there, the
string having been disposed before the find arm's second phase and
never built on the scan arms.

## Consumers

The dispatch is reached only through the index selector 0x5f6c2a0's
tail jump at 0x5f6c2d7 (census: no direct calls, no stored qwords, no
RELATIVE addends). The selector — itself pinned by the RE-001
later-group predicate item — is called from four sites
(0x5f6d67e in the later-group predicate 0x5f6d600, 0x5ebd196 in the
selector-inversion wrapper, and the site-only 0x5df1739 and
0x5df186a), and forwards (rdi = [obj], esi = 1 if the index is
positive else 0, rdx = the selected file entry, rcx/r8 = the
caller's two record pointers). A census surprise in this item's
favour: the brief pointer the dispatch receives is that selected
entry pointer value, and the dispatch treats it as a brief base
(count at +0, array at +8); both readings are stated as the register
contract, and resolving the caller's layout is the consumer items'
ground, not this item's.

## Validation

tools/selector_dispatch_6a820_115.py models the window;
tests/test_selector_dispatch_6a820_115.py carries the model checks.
differential.py in this packet runs the native window under Unicorn
against the model (both compare routes, the builder and finder
emulated at their entry points with the contracts above, the slow
route's literal (1, 1) arguments asserted on every slow call):
1,020 directed and seeded-random cases across two seeds agree.
verify.py re-derives the digest binding, the manifest, the excerpts
byte-for-byte, the gate instructions against the raw bytes, the FDE
ranges, the census, the model tests and, when the unicorn package is
available, the differential.

## Unknowns, stated explicitly

- The two consumer items describe this dispatch as 964 bytes; its
  FDE range and the RE-002 vendor window both give 908 bytes, and
  the next FDE starts at 0x5f6abb0 after 4 int3 bytes. The 964
  figure is not reproduced from the FDE and is not used here.
- What the finder's ordering callee 0x5f64630 compares (its
  lower-bound predicate) is not pinned; only the finder's
  pointer-to-index conversion is read.
- Whether the compare routes, the builder or the finder mutate the
  brief or the entries is not pinned; the model treats count, base
  and entries as stable across one call, as the sibling items do.
- The entry fields outside +0x30..+0x50 are never read by this
  window and are not claimed.
- The concrete function behind the fast route's [[cmp+0x20]+0x10]
  is not identified beyond its call contract; the guard establishes
  only that the slow route through slot +0xd0 was not taken.
