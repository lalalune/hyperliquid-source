# RE-001: node #115 list range copy-insert 0x5f12320

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the whole 243-byte
routine at 0x5f12320 do, end to end? It is the range-insert body of a
std::list whose nodes are 0x18 bytes: it deep-copies the source range
[rdx, rcx) into a destination list before a position node. The RE-002
vendor census identifies the FDE (0x5f12320..0x5f12413) as a
librocksdb-sys 0.11.0+8.1.1 build copy of
`std::list<rocksdb::MemTable*>::insert(const_iterator,
_List_const_iterator, _List_const_iterator)` (.isra.0) — identification
only; this packet pins the behaviour from the bytes. The routine is the
helper open PR #3391 (copy-on-write move helper 0x5f12840) cites by
contract only; both of its call sites are in that helper, and this
packet is the body those contracts describe.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` at the head of the landing pad (0x5f12407) is a genuine
instruction present in the target binary, not a placeholder.
Instruction-level detail lives only in the whole-function verbatim
excerpts in main.txt, cleanup.txt and site.txt; the JSON in this
packet holds semantic records only. The objdump commands that produced
the excerpts are recorded in export_excerpts.py, which regenerates
them byte-for-byte.

## Semantics, stated literally

Arguments (System V): rdi = the destination list object — its header
node is at object +0x00/+0x08 and its size field is the qword at
object +0x10; rsi = the insertion position node (an iterator into the
destination list); rdx = the first source node; rcx = the source end
node (exclusive). The source range is the forward chain [rdx, rcx)
linked by the +0x00 next pointers. A node is 0x18 bytes: next at
+0x00, prev at +0x08, payload qword at +0x10.

- Empty range (rdx == rcx): the routine returns at once. It writes
  nothing at all — not even the destination size.
- Non-empty range: the copies are first built in a private on-stack
  temporary list. For each source node in order, one fresh 0x18-byte
  node is allocated with operator new (PLT 0x63f0dd0) and the body's
  only own store to it copies the payload qword (+0x10) from the
  source node; then _M_hook (PLT 0x63f1090) links it before the temp
  header, i.e. at the temp list's tail, so the copies preserve source
  order. A copied node's +0x00/+0x08 fields hold whatever _M_hook
  writes; the body itself never stores them, and it never reads a
  source node's +0x08.
- The finished temp chain is spliced before the position node with a
  single _M_transfer call (PLT 0x63f13c0): _M_transfer(position,
  temp first, temp header). The destination list's links change only
  in that one call. (The guard between the copy loop and the call —
  skip when the temp list is empty — is dead on every reachable path:
  a non-empty range hooks at least one copy.)
- The destination size at +0x10 then grows by the copied count, in a
  single add placed after the transfer returns.
- Only then is the temp list drained: each node still linked in it is
  deleted with sized operator delete (node, 0x18) (PLT 0x63f0d80).
  A contract-faithful transfer empties the temp list, so the loop
  normally deletes nothing; it is live code exactly when the
  transfer's postcondition does not hold.
- The source nodes are never written; the destination size is never
  read. Neither call site reads rax after the call.

## Exception landing pad (stated literally)

The FDE's LSDA carries exactly one call-site entry, for the
operator-new call in the copy loop (body range 0x5f12375..0x5f1237a),
landing on the pad at 0x5f12407. The pad moves the exception object
to rbx and jumps directly into the shared cleanup block at
0x5f122e0 (in the neighbouring FDE 0x5f122e0..0x5f12318, excerpted in
cleanup.txt). That block walks the temp chain from the temp header's
next pointer and raw-deletes every node in chain order (size 0x18,
no unhook), then calls _Unwind_Resume (PLT 0x63f0a50) with the
original exception object. No _M_transfer has run at that point and
the size add has not run, so the destination list is byte-for-byte
untouched on this path. The other PLT calls (_M_hook, _M_transfer,
operator delete) have no landing pad: an exception escaping them
terminates.

## Call sites (both, whole-file census)

* 0x5f128b5 (in 0x5f12840..0x5f129a6): rdi = the destination object
  (the list object is its first list, at +0x00); rsi = rdi, the
  destination first list's header, so the copies land at its tail;
  rdx = the source first list's first node; rcx = the source object's
  first-list header. The caller checks first node != header first, so
  the call only happens for a non-empty range.
* 0x5f12924 (same caller): rdi = rsi = the destination object +0x18 —
  the destination's second list taken as its own list object (header
  at +0x00, size at +0x10, i.e. object +0x28); rdx = the first
  surviving source node of the source object's second list, after the
  caller's lockstep adjustment walk; rcx = the source object +0x18,
  the source second list's header. The caller compares the adjusted
  first against the end and skips the call when the surviving range
  is empty.

So the routine's empty-range early return is unreachable from both of
its only callers; it is pinned here as body behaviour, not as a path
any caller takes. Excerpted in site.txt.

## Relation to the #3391 contract

PR #3391 cited this routine by contract, reading its behaviour off
the call sites. Every observable claim in that contract is confirmed
by the body: deep copy, fresh 0x18-byte nodes, payload qword copied,
source order preserved, destination size grown by the copied count,
source unmodified. Two mechanism details differ from a plain reading
of the contract: the copies reach the destination through one bulk
splice of a fully built temp chain, not through per-node tail
appends; and the header the contract spoke of is not a separate
argument — the destination header is part of the object in rdi, and
the second argument is the insertion position (both call sites pass
the destination list's own header, so inserts land at the tail).

Distinct from RE-001-drain-driver-115 (merged): its README states
this list-move area was judged too tangled to pin honestly in earlier
cycles and claims only call sites there; the windows and claims do
not overlap. No open PR title among all 783 open PRs mentions
0x5f12320, and a body search for 5f12320 returns no open PR (swept
2026-11-06).

NOT claimed: caller semantics beyond the two sites' argument setups
and non-empty guards; what the payload qwords denote (the vendor
census's MemTable* identification is not used by any claim here);
any behaviour when the source chain does not reach the end node (the
native body would keep allocating until it faults; the model raises
instead); the contents of a copy's +0x00/+0x08 before _M_hook writes
them; any try region beyond the single LSDA call-site entry.

## Verification

The packet's verify.py checks: the work binary digest against the
provenance entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every excerpt
instruction byte-for-byte against the raw binary; three extra spot
instructions byte-for-byte against a fresh objdump run and the raw
binary (0x5f12375, 0x5f128b5, 0x5f12924); the FDE ranges for the
routine, the cleanup block and the caller against a fresh frame dump;
census consistency (callers.tsv against a fresh whole-file scan:
exactly 2 direct calls, 0 tail jumps, 0 stored qwords, 0 RELATIVE
addends); the semantic records; and the model tests in
tests/test_list_copy_insert_12320_115.py (30 checks: empty range,
order, middle insertion, partial range, the body's single own store,
the drain loop under a no-op transfer, and the allocation-failure
cleanup path).

The packet's differential.py additionally runs the routine's real
243 bytes under Unicorn against the model on 48 cases (structured
images, a no-op-transfer drain case, and 40 randomised images over a
random-filled window), comparing the whole data window, the whole
heap window, the allocator state, the callee-saved registers and the
stack pointer: 48 cases, 0 mismatches. The four PLT callees are
answered with the libstdc++ semantics stated above, on both sides
alike — the differential tests this body's own instructions, not the
library primitives' bytes. The exception path is not emulated
(Unicorn has no unwinder); it is pinned by the model tests and the
LSDA reading above.

Environment limits, stated honestly: this VM has no cargo/rustc and
no Ghidra/Java, so the model layer is Python and the evidence is
objdump/readelf output against the digest-verified local binary. No
full node build or binary-equivalence claim is made.
