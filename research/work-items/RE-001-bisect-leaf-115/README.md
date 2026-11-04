# RE-001: node #115 bisect leaf 0x5f6bba0

Task: RE-001. Bounded question: what does the 106-byte function at
0x5f6bba0 in the node #115 binary return for a target key, and how
are its records laid out?

## Window

- Bisect leaf: 0x5f6bba0..0x5f6bc0a (106 bytes, FDE file offset
  0x1004d00, length field 0x10, CIE at .eh_frame start, augmentation
  "zR", no LSDA field). See frames.txt.
- Binary: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  bound in provenance/artifacts.json as artifacts/node/115/hl-node.
- The 9 bytes at 0x5f6bbf7..0x5f6bc00 (a nopw plus two zero bytes)
  are alignment padding between the return and the high-side block;
  they are inside the FDE range but are not instructions of the
  search. The `endbr64` at 0x5f6bba0 is a genuine instruction present
  in the target binary, not a placeholder.

## Semantics, stated literally

Object fields (offsets from the object base):

- +0xad8: begin pointer of the record array.
- +0xae0: end pointer of the record array.

Each record is 16 bytes. A record's key is reached through two
loads: the record's first qword is an element pointer, and the key is
the first qword at the address held in the element's first qword, i.e.
key = [[record]]. No other record or element field is read.

Search rule, exactly as the native loop runs:

1. diff = (end - begin) as a wrapping 64-bit difference, read signed.
   If diff <= 0, return the begin pointer at once, without reading
   any record.
2. Otherwise count = diff >> 4 (arithmetic shift, so a byte span that
   is not a multiple of 16 floors to whole records). With lo = begin
   and remaining = count, loop:
   - half = remaining >> 1 (arithmetic; remaining > 0 at the loop head).
   - mid = lo + half * 16 bytes; key = [[record at mid]].
   - If key >= target under UNSIGNED comparison (native cmp + jae):
     if half == 0, return lo; else remaining = half and repeat.
   - Else (key < target): remaining = remaining - half - 1;
     lo = mid + 16 bytes; if remaining > 0, repeat; else return lo.
3. The result is a record pointer: the first record whose key is >=
   the target, or the pointer one past the last record examined when
   every examined key is below the target. For a well-formed array
   (byte span exactly 16 * record count) that is the usual lower
   bound, or the end pointer when the target exceeds all keys.

The model in tools/bisect_leaf_115.py returns the same result as an
index relative to begin, and reproduces the loop exactly rather than
substituting an idealised lower bound, so a partial byte span behaves
as the native code does: a span of 8 with one record returns begin
when that record's key is >= the target and begin + 16 when it is
below it.

## Consumers

Census (whole-file scan, reproduced by census.py and re-checked by
verify.py): exactly 14 direct calls, 0 tail jumps, 0 stored qwords,
0 R_X86_64_RELATIVE addends:

- 0x5f463fe, 0x5f4a482, 0x5f4ad3a, 0x5f4bcb1, 0x5f50795, 0x5f52f32,
  0x5f709d5, 0x5f71073, 0x5f711ea, 0x5f71211, 0x5f71238, 0x5f7126e,
  0x5f71312, 0x5f7f456 (sites only; the containing functions are not
  modelled here).

The leaf makes no calls of its own, so the search above is the whole
behavior; the 14 sites are what make it observable.

## Assumptions and unknowns

- Records are 16 bytes and sorted by key in the callers' use; the leaf
  itself does not check sortedness, and an unsorted array returns
  whatever the loop lands on, as the native code would.
- A null element pointer, a null key-holder pointer, or a record
  array shorter than the byte span would be read unchecked by the
  native code; the model raises BisectLeafError for those inputs
  instead.
- The containing functions of the 14 call sites are not claimed here;
  what each caller passes as the target key is left open.

## Verification

verify.py checks, all against the real binary: digest and provenance
binding, MANIFEST.sha256, excerpt regeneration byte-for-byte from a
fresh objdump run, 5 gate + 3 extra instructions byte-for-byte
against a fresh objdump run and against the raw binary bytes, the FDE
range, the census site lists, and the model tests (27 checks across 7 groups,
including unsigned high-bit ordering, partial spans, and guards).
Run from the clone root:

  python3 research/work-items/RE-001-bisect-leaf-115/verify.py

Environment honesty: pytest is not installed on this VM, so the
pytest-style test file runs under plain python3 via its `__main__`
runner. `make doctor` fails on missing providers (pre-existing);
`make verify` fails on the LFS-pointer artifact here (pre-existing) —
this packet binds to the materialized work/hl-node-115.bin instead.
