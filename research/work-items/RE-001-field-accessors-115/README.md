# RE-001: node #115 field accessors 0x5d8d0c0, 0x5d8d0d0 and 0x5d8d0e0

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what do the three adjacent
leaves at 0x5d8d0c0 do, end to end, and where are they used? It is a
complete behavior, not a lone-window fragment: three whole leaves —
a +0x70 dword getter, a +0x70 unsigned-max raiser, and a +0x18 qword
getter — with ALL eight of their direct call sites in the binary
(whole-file census), including the two call chains that tie them to
the record-fill routine and to the field-raise sequence pinned by
open PRs #2378 and #2374. The +0x70 getter's own semantics were
explicitly left unclaimed by open PR #2378, which used it only as a
callee; this item pins that callee, its +0x70 raiser sibling, and
the adjacent +0x18 getter with all of their consumers.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` instructions at the head of each leaf are genuine
instructions present in the target binary, not placeholders.
Instruction-level detail lives only in the whole-function verbatim
excerpt in main.txt and the verbatim site excerpts; the JSON in this
packet holds semantic records only. The objdump command that produced
the excerpts is recorded in export_excerpts.py, which regenerates
them byte-for-byte.

## Semantics, stated literally

All three leaves take an object in rdi, make no calls, and are
leaf-sized (8, 16 and 9 bytes including `endbr64`):

* 0x5d8d0c0 (FDE 0x5d8d0c0..0x5d8d0c8): returns the dword at
  obj+0x70, zero-extended to 64 bits in eax. It writes nothing.
* 0x5d8d0d0 (FDE 0x5d8d0d0..0x5d8d0e0): takes a second argument in
  esi and stores the unsigned 32-bit maximum of the dword at
  obj+0x70 and that value back at obj+0x70. The sequence is
  `mov 0x70(%rdi),%eax; cmp %esi,%eax; cmovb %esi,%eax;
  mov %eax,0x70(%rdi)`: the move happens exactly when the current
  value is below the incoming value as unsigned 32-bit quantities,
  so equality stores nothing and the result is exactly
  max(current, value). It returns void.
* 0x5d8d0e0 (FDE 0x5d8d0e0..0x5d8d0e9): returns the qword at
  obj+0x18 in rax. It writes nothing.

The int3 bytes between the leaves (0x5d8d0c8..0x5d8d0cf) are
padding, not code; the next leaf starts at 0x5d8d0d0 and the
third at 0x5d8d0e0.

## Call sites (all eight, whole-file census)

The +0x70 getter (0x5d8d0c0), four sites, all passing a +0x40
subobject as rdi:

* 0x5f6eb88 (in the record-fill routine 0x5f6eb50..0x5f6eb96,
  open PR #2378): rdi = the record-fill source's +0x40 subobject;
  the taken arm only (the gate byte at dst+0x134 is nonzero, via
  the jne at 0x5f6eb75). After the call the routine stores 1 at
  dst+0x7d and the 32-bit result as a dword at dst+0x60.
  Excerpted in site-recordfill.txt.
* 0x5f96156 (in 0x5f95b80..0x5f98c8d): rdi = the qword at
  [rbx+0x40]; after the call the caller reloads rdi from
  [rbx+0x40], tests the result, jumps to 0x5f9782c when nonzero,
  and otherwise falls through to load the qword at [rdi+0x110].
  Excerpted in site-getter-96156.txt.
* 0x5f97841 (in 0x5f95b80..0x5f98c8d, reached from the nonzero
  arm of 0x5f96156): rdi = the qword at [rbx+0x40], carried
  unchanged along the jump path (the block at 0x5f9782c writes
  only rax and r14 before the call); dst r14 = the qword at
  (qword at (qword at [rbp-0x690] + 0x268) + 0x48). After the call
  the caller stores 1 at dst+0x7d and the 32-bit result as a dword
  at dst+0x60 — the same store pair as the record-fill arm, on a
  different destination — then jumps to 0x5f96167.
  Excerpted in site-getter-97841.txt.
* 0x5f9ab06 (in 0x5f9a580..0x5f9aca9): rdi = the qword at
  [rbx+0x40]; after the call the caller moves the result to edi,
  loads rcx from [rbx+0x128], rdx from [rbx+0x108], rax from
  [rbx+0xd8], rsi from [rbx+0xd0] and r8 from [rbp-0x450], then
  pushes r14 and pushes rdi — the getter's result, still in rdi —
  as a stack argument of the following call.
  Excerpted in site-getter-9ab06.txt.

The +0x70 raiser (0x5d8d0d0), one site:

* 0x5f9dfa1 (in 0x5f9daf0..0x5f9eccd): rdi = the qword at
  [[rbp+0x60]+0x40], esi = the dword at [rbp+0x170]. It is the
  first of a four-leaf raise sequence on the same logical object:
  after it the caller raises the +0xe0 qword field of [rbp+0x60]
  with open PR #2374's max leaf (value [rbp+0x178]), then raises
  its +0xd8 field twice with #2374's advance leaf (values
  [rbp+0x160] and [rbp+0x158]). Excerpted in site-shared.txt.

The +0x18 getter (0x5d8d0e0), three sites, all testing the result
against a small bound:

* 0x5d95e21 (in 0x5d954b0..0x5d96890): rdi = the qword at
  [rbx+0x958]; after the call the caller loads rsi from
  [rbx+0x588], compares the result against 9 unsigned, and jumps
  to 0x5d962d0 when above. Excerpted in site-get18-95e21.txt.
* 0x5de3c20 (in 0x5de3340..0x5de404e): rdi = the qword at
  [[rbx+0x68]+0x40]; after the call the caller compares the result
  against 1 unsigned, and jumps to 0x5de33ce when at or below.
  Excerpted in site-get18-3c20.txt.
* 0x5e8ecdd (in 0x5e8e4a0..0x5e8ee70): rdi = the qword at
  [[rbx+0x68]+0x40]; after the call the caller compares the result
  against 1 unsigned, and jumps to 0x5e8ed23 when at or below.
  Excerpted in site-get18-ecdd.txt.

Distinct from open PR #2378 (record-fill 0x5f6eb50): that routine
is the caller of the getter at 0x5f6eb88, not the getter itself,
and #2378 explicitly left the getter's semantics unclaimed.
Distinct from open PR #2374 (advance/max leaves 0x5f6f400/
0x5f6f430): those are the later leaves of the shared sequence at
0x5f9dfb1/0x5f9dfc1/0x5f9dfd1, not the raiser at 0x5f9dfa1, and
no claim here re-states their semantics beyond the sequence order.

NOT claimed: caller semantics beyond the sites above; what the
objects, the +0x40 subobjects, or the +0x18/+0x70 fields denote;
what happens on any branch target past a site; the following call
at 0x5f9ab06 beyond its argument setup; any relation between the
three leaves beyond their adjacency, their shared +0x70 field for
the first two, and the common +0x40-subobject argument shape at
the getter and raiser sites.
