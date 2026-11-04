# RE-001: node #115 flag-variant index leaf 0x5f6b740 with its sole call site

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the whole 19-byte
flag-variant leaf at 0x5f6b740 compute from one object field and one
caller-supplied flag byte, and what does its ONLY direct call site in
the binary do with the result? The leaf is modelled end to end,
together with its sole site and that site's full argument setup and
both result arms — a complete behavior, not a lone-window fragment.
The leaf takes an object pointer and a flag whose low byte only
participates, reads one dword field, and returns one 32-bit value;
it makes no call and writes nothing.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` at the head of the leaf window is a genuine
instruction present in the target binary, not a placeholder.
Instruction-level detail lives only in the whole-function verbatim
excerpts in main.txt and the verbatim site excerpt in site.txt; the
JSON in this packet holds semantic records only. The objdump command
that produced the excerpts is recorded in export_excerpts.py, which
regenerates them byte-for-byte.

## Semantics, stated literally

### Flag-variant leaf 0x5f6b740 (19 bytes, FDE 0x5f6b740..0x5f6b753)

* Takes obj in rdi and a flag in rsi, returns a 32-bit value in eax.
  Only the low byte of rsi participates; the upper bytes of rsi are
  never read. The leaf makes no call and writes nothing.
* Return value, all arithmetic modulo 2**32: the dword at obj + 0x10,
  minus 2, plus 1 when the flag low byte is zero, plus 0 when it is
  nonzero. Equivalently: flag low byte zero returns field - 1;
  flag low byte nonzero returns field - 2 (both wrapping).
* Nothing else is read. In particular the leaf never reads any byte
  at obj + 0xa90 or any other field, and its result never depends
  on anything but the dword at obj + 0x10 and the flag low byte.

Consequences, stated literally: the two arms differ by exactly 1;
field 0 with a zero flag returns 0xffffffff (wrap), field 0 with a
nonzero flag returns 0xfffffffe; field 2 with a zero flag returns 1
and field 2 with a nonzero flag returns 0; a flag value of 0x100
behaves exactly like flag 0 (low byte zero) and 0x101 exactly like
flag 1.

### Relation to the sibling gate leaf (reference only, not re-claimed)

The sibling leaf at 0x5f6b720 (open PRs #2330/#2331) reads the same
+0x10 dword and subtracts the same constant 2, but its gate is a
stored byte at obj + 0xa90 (zero gate returns field - 2, nonzero
gate returns 0), while this leaf's gate is the caller-supplied flag
low byte and its zero arm returns field - 1, not field - 2. The two
leaves are distinct functions with distinct gates; nothing about the
sibling's callers or object type is claimed here.

## Call site (site-only)

Census (whole-file scan, reproduced by census.py and re-run inside
verify.py): leaf exactly 1 direct call, 0 tail jumps,
0 stored qwords, 0 RELATIVE addends.

* 0x5df5bff, inside 0x5df0f40..0x5df1e22: the caller first loads
  rax from [rax + 0x710] at 0x5df5be8, then loads esi as the
  zero-extended byte at [r15 + 0x4c3] at 0x5df5bef, then loads rdi
  from [rax + 0x30] at 0x5df5bf7 and adds 0x40 at 0x5df5bfb, so the
  leaf's obj is [rax + 0x30] + 0x40 (that is, the leaf reads the
  dword at [rax + 0x30] + 0x50) and its flag low byte is the byte at
  [r15 + 0x4c3]. What rax and r15 denote in the caller is not
  claimed.
* Result disposition, both arms: the caller compares the leaf's
  return against ebx at 0x5df5c04. When they differ, the jne at
  0x5df5c06 jumps to 0x5df4ad0 at once and the virtual call below
  never runs. When they are equal, the caller falls through, loads
  rdi from [r15 + 0x318] at 0x5df5c0c, zeroes esi, loads rax from
  [rdi], and makes the virtual call at 0x5df5c18 (slot +0x200).
  The virtual call's result is then tested at 0x5df5c1e: when it
  is less than or equal to zero (signed), the jle at 0x5df5c20
  rejoins the not-equal path at 0x5df4ad0; only a positive virtual
  result continues past 0x5df5c20. So leaf equality is necessary
  but not sufficient for continuing past the site: the virtual
  call must also return positive.
* The shared destination 0x5df4ad0 is not characterized here; it
  is the same address both arms reach, and nothing about what
  happens there is claimed.

## Not claimed

Caller semantics beyond the site arguments and result disposition
above; what rax, r15, ebx, or the fields at +0x710, +0x4c3, +0x30,
+0x318 denote; the virtual call's semantics or its target; what
happens at 0x5df4ad0 or past 0x5df5c20; any meaning for the +0x10
field or the flag byte beyond the rule above; the sibling leaf's
behavior beyond the reference paragraph above. This item is
distinct from the open PRs that share its caller function region
only by address: no address in this packet overlaps any open PR
(the leaf 0x5f6b740 and its site 0x5df5bff appear in no open PR
title or code search).
