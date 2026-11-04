# RE-001: node #115 storage-release leaf 0x5f78000 and container-clear leaf 0x5f78030 with their seven call sites

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what do the two adjacent small
leaves at 0x5f78000 and 0x5f78030 do to one object each, and where does
the binary call them? The two leaves are modelled end to end, together
with ALL seven of their direct call sites in the binary (whole-file
census) — a complete behavior, not a lone-window fragment. The leaves
take no other input and make no calls except the release leaf's single
tail jump to operator delete.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` at the head of each leaf window is a genuine
instruction present in the target binary, not a placeholder.
Instruction-level detail lives only in the whole-function verbatim
excerpts in main-release.txt and main-clear.txt and the verbatim site
excerpts; the JSON in this packet holds semantic records only. The
objdump command that produced the excerpts is recorded in
export_excerpts.py, which regenerates them byte-for-byte.

## Semantics, stated literally

### Storage-release leaf 0x5f78000 (33 bytes, FDE 0x5f78000..0x5f78021)

* Takes obj in rdi, returns void.
* Read begin = the qword at obj + 0x00.
* If begin is zero: return at once. No delete happens, and nothing
  is written.
* Otherwise: read cap = the qword at obj + 0x10, and tail-jump to
  operator delete (PLT 0x63f0d80) with (begin, cap - begin mod 2**64).
  The leaf returns to its caller through that tail jump.
* The leaf itself writes nothing: obj + 0x00 and obj + 0x10 are left
  exactly as they were. No meaning for the fields beyond the offsets
  read is claimed; in particular, whether obj + 0x10 is a capacity
  end or some other bound is not pinned beyond the subtraction the
  leaf performs.

Consequences, stated literally: a zero begin never deletes, even when
obj + 0x10 is nonzero; a nonzero begin always deletes exactly once,
with the byte size wrapping mod 2**64 when cap is below begin.

### Container-clear leaf 0x5f78030 (41 bytes, FDE 0x5f78030..0x5f78059)

* Takes obj in rdi, returns void, makes no calls.
* If the qword at obj + 0x00 is nonzero, store zero there; a zero
  qword is left alone (the store is skipped, same final value).
* Read begin = the qword at obj + 0x190 and end = the qword at
  obj + 0x198. If begin differs from end, store begin at obj + 0x198;
  if they are already equal, store nothing.
* Nothing else is read or written. The qword at obj + 0x190 itself
  is never written, and the qword at obj + 0x1a0 is never touched.

Consequences, stated literally: after the leaf, obj + 0x00 is zero
and obj + 0x198 equals obj + 0x190, whatever the entry values were;
an already-empty sub-container (begin == end) is a no-op for the
second step, and the leaf never frees any storage.

## Call sites (site-only)

Census (whole-file scan, reproduced by census.py and re-run inside
verify.py): release leaf exactly 5 direct calls, 0 tail jumps,
0 stored qwords, 0 RELATIVE addends; clear leaf exactly 2 direct
calls, 0 tail jumps, 0 stored qwords, 0 RELATIVE addends.

Release leaf:

* 0x5f7f22f, inside 0x5f7ede0..0x5f7f280 (landing pad): rdi = the
  qword at stack slot 0x28(%rsp). After the call the caller moves
  rbx to rdi and calls __cxa_begin_catch.
* 0x5f7f251, inside the same caller (landing pad): rdi = the qword
  at stack slot 0x28(%rsp) again, the same object as at 0x5f7f22f.
  After the call the caller calls __cxa_rethrow.
* 0x5f7f28b, inside 0x5f7f280..0x5f7f375 (cleanup): rdi = r13.
  After the call the caller sets rbp to rsp + 0xe0 and moves rbp to
  rdi for the clear call.
* 0x5f7f2a0, inside the same cleanup caller: rdi = the rsp + 0x270
  object. After the call the caller tests the qword at stack slot
  0x50(%rsp) and jumps to 0x5f7f2b7 when it is zero.
* 0x5f7f2fa, inside the same cleanup caller: rdi = r13, the same
  object as at 0x5f7f28b. After the call the caller jumps back to
  0x5f7f290, the clear-call setup.

Clear leaf:

* 0x5f7f247, inside 0x5f7ede0..0x5f7f280 (landing pad): rdi = r12,
  reached only when the qword at stack slot 0x8(%rsp) is zero (the
  caller branches to 0x5f7f25b otherwise). After the call the caller
  loads the qword at stack slot 0x28(%rsp) into rdi and calls the
  release leaf again (site 0x5f7f251).
* 0x5f7f293, inside 0x5f7f280..0x5f7f375 (cleanup): rdi = rbp, the
  rsp + 0xe0 object. After the call the caller loads rsp + 0x270
  into rdi for the release call (site 0x5f7f2a0).

## Observed sequences (observed, not wider caller claims)

Cleanup function 0x5f7f280..0x5f7f375, at entry, in order: release
of the r13 object (0x5f7f28b), clear of the rsp + 0xe0 object
(0x5f7f293), release of the rsp + 0x270 object (0x5f7f2a0). Later
in the same function the r13 object is released again (0x5f7f2fa)
and control jumps back to the clear-call setup (0x5f7f290); the
intervening work in that function is not claimed.

Landing pad in 0x5f7ede0..0x5f7f280, in order: release of the
stack-slot 0x28(%rsp) object (0x5f7f22f), then, only when the qword
at stack slot 0x8(%rsp) is zero, clear of the r12 object (0x5f7f247)
and a second release of the stack-slot 0x28(%rsp) object (0x5f7f251).
The surrounding exception-handling calls and the nonzero-slot arm
are not modelled beyond the site notes above.

## Not claimed

Caller semantics beyond the site arguments, site conditions and
post-call steps; any meaning for the +0x00, +0x10, +0x190 or +0x198
fields beyond the rules above; the contents of the objects at
[rsp + 0x28], r12, r13, rsp + 0xe0 or rsp + 0x270 beyond the field
offsets read and written; the intervening work of either caller
function; the behavior of operator delete itself beyond receiving
(begin, size). This item is distinct from open PR #2133 (destructor
pair 0x5f10180/0x5f10d00) and open PR #2235 (recursive tree teardown
0x5f53f50); no address in this item overlaps either.
