# RE-001: node #115 record-fill routine 0x5f6eb50 with its sole call site

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the whole 70-byte
record-fill routine at 0x5f6eb50 do to one destination record, and
where does the binary call it? The routine is modelled end to end,
together with its ONLY direct call site in the binary (whole-file
census) and that site's two entry paths — a complete behavior, not a
lone-window fragment. The routine takes a source object, a destination
record and a pointer to one qword, and makes one conditional call to
the callee at 0x5d8d0c0.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` at the head of the routine window is a genuine
instruction present in the target binary, not a placeholder.
Instruction-level detail lives only in the whole-function verbatim
excerpts in main.txt and the verbatim site excerpt in site.txt; the
JSON in this packet holds semantic records only. The objdump command
that produced the excerpts is recorded in export_excerpts.py, which
regenerates them byte-for-byte.

## Semantics, stated literally

### Record-fill routine 0x5f6eb50 (70 bytes, FDE 0x5f6eb50..0x5f6eb96)

* Takes src in rdi, dst in rsi, and a pointer in rdx to one qword.
  Returns void, makes no call except the conditional callee call
  below.
* Always, in order: dst + 0x58 = the qword at src + 0xd8;
  dst + 0x7c = 1 (one byte); dst + 0x7f = 1 (one byte);
  dst + 0x70 = the qword at [rdx]. The order of the +0x7c and +0x7f
  stores relative to the [rdx] load does not matter: no stored
  field is re-read.
* Then read the byte at dst + 0x134. When that byte is zero:
  return at once. No callee call happens, and dst + 0x7d and
  dst + 0x60 are left exactly as they were.
* When that byte is nonzero: call the callee at 0x5d8d0c0 with
  (src + 0x40, dst); then store 1 in the byte at dst + 0x7d and
  store the callee's 32-bit return value (eax) at dst + 0x60 as a
  dword. The four bytes at dst + 0x64..0x67 are never written by
  this routine.
* Nothing else is read or written by this routine. In particular
  src + 0x40 is read only on the nonzero-gate arm, so a caller that
  passes the zero arm never touches it.

Consequences, stated literally: after the routine, dst + 0x58,
dst + 0x70, dst + 0x7c and dst + 0x7f are always set as above,
whatever the gate byte was; dst + 0x7d is 1 and dst + 0x60 holds
the callee's return exactly when the gate byte was nonzero on
entry; a zero gate byte leaves dst + 0x7d and dst + 0x60 untouched
even when the callee would have returned something.

## Call site (site-only)

Census (whole-file scan, reproduced by census.py and re-run inside
verify.py): routine exactly 1 direct call, 0 tail jumps,
0 stored qwords, 0 RELATIVE addends.

* 0x5f95d03, inside 0x5f95b80..0x5f98c8d: rdi = rbx (the source
  object); rsi = the destination record pointer the caller loaded
  at 0x5f95c61 from [rax], where rax came from the caller's
  incoming rax + 0x48 at 0x5f95c4b; rdx = the stack address
  -0x658(%rbp), so the qword the routine stores at dst + 0x70 is
  the caller's stack slot at -0x658(%rbp). The caller stores a
  different, earlier record pointer to -0x690(%rbp) at 0x5f95c4f
  before loading the destination; that saved pointer is not the
  routine's dst.
* Entry paths into the call setup at 0x5f95ce4: (a) the jne at
  0x5f95cd5, whose flags come from an instruction before this
  excerpt (not claimed); (b) fall-through when that branch is not
  taken and the byte at dst + 0x134 is nonzero — the caller tests
  exactly the routine's gate byte at 0x5f95cd7 and jumps to
  0x5f964bc when it is zero. So on path (b) the routine's taken
  arm is guaranteed, while on path (a) the gate byte is untested
  by the caller and either arm may run. Both arms of the routine
  are reachable from this sole site. (The caller also tests the
  neighboring byte at dst + 0x135 at 0x5f95c7a; no relation to the
  gate is claimed.)
* After the call the caller reloads the saved earlier pointer from
  -0x690(%rbp) into rax, loads the qword at rax + 0x268, then
  loads the qword at that result + 0x48 into rdx.

## Not claimed

Caller semantics beyond the site arguments, entry paths and
post-call steps above; the callee at 0x5d8d0c0's semantics, and any
effect it may have on dst beyond returning eax (the routine's own
writes after the call are pinned above); any meaning for the
+0xd8, +0x40, +0x58, +0x60, +0x70, +0x7c, +0x7d, +0x7f or +0x134
fields beyond the rules above; the contents of the caller's stack
slots beyond the offsets read and written; the intervening work of
the caller function. This item is distinct from the open PRs that
share its caller function (e.g. #2374, whose max-store site
0x5f9846d is in the same caller but claims a different routine);
no address in this item overlaps any open PR.
