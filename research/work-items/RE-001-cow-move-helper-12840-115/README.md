# RE-001: node #115 copy-on-write move helper 0x5f12840

## Bounded question

The merged drain-driver packet (RE-001-drain-driver-115) mapped
the copy-on-write prepare at 0x5f13f90 end to end, but left two
of its helpers by contract only: "The field-by-field contents
moved by 0x5f12840 and established by 0x5f12a00 are unknown;
both are by contract only." The init helper 0x5f12a00 has since
been pinned (RE-001-refcount-increment-12a00-115). What does
the move helper at 0x5f12840 -- called by the prepare as
move(new, outer + 0x18, inner) on the fresh 0x50-byte object --
actually write into the new object, field by field, and what
does it do to the two lists and their payloads?

## Answer, pinned to the target

The routine (FDE `0x5f12840..0x5f129a6`, 358 bytes, CIE
0x730230 with an LSDA) takes rdi = destination object, rsi = a
pointer it only stores, rdx = source object, and returns void.
The destination is a 0x50-byte object: two std::list members
(header at +0x00 with its count at +0x10; header at +0x18 with
its count at +0x28), a dword at +0x30, a qword at +0x38, the
+0x40 reference-count dword, and a stored pointer at +0x48.
List nodes are 0x18 bytes (+0x00 next, +0x08 prev, +0x10
payload).

**Prologue (unconditional, in instruction order).** Both list
headers are self-linked empty and both counts zeroed; the
+0x30 dword and the +0x38 qword are copied from the source;
the +0x40 count is set to 0; rsi is stored at +0x48. One field
is conspicuously not written on any path:

| offset | width | what the routine does |
| ------ | ----- | --------------------- |
| `+0x00` | 8 | list-1 header next = destination (self-link) |
| `+0x08` | 8 | list-1 header prev = destination (self-link) |
| `+0x10` | 8 | list-1 count = 0 (raised later only by the copy helper's count add) |
| `+0x18` | 8 | list-2 header next = destination + 0x18 (self-link) |
| `+0x20` | 8 | list-2 header prev = destination + 0x18 (self-link) |
| `+0x28` | 8 | list-2 count = 0 (same note as +0x10) |
| `+0x30` | 4 | copied verbatim from source +0x30 |
| `+0x34` | 4 | **never written** -- the copies at +0x30 (4 bytes) and +0x38 (8 bytes) leave it with whatever the allocation held |
| `+0x38` | 8 | copied verbatim from source +0x38 |
| `+0x40` | 4 | reference count = 0 (the prepare's init callee 0x5f12a00 then increments it; pinned separately) |
| `+0x48` | 8 | the rsi argument, stored verbatim, never dereferenced |

**Self-copy guard.** If rdx == rdi, the routine returns right
after the prologue. The sole caller passes a fresh allocation,
so the guard is unreachable from it; it is pinned as written.

**List 1.** If the source list 1 is nonempty, the routine
calls the list-copy helper 0x5f12320 at 0x5f128b5 (by contract,
below), which deep-copies the source list 1 into the
destination list 1 -- fresh 0x18-byte nodes carrying the same
payload pointers in the same order -- and adds the copied
count to +0x10. The routine then walks its new list 1 and
increments the dword at payload +0x70 of every node (plain
`addl`: wraps modulo 2^32, no lock prefix). If the source
list 1 is empty, the phase is skipped entirely. The source
list itself is never modified.

**List 2, as written.** The body carries a full reconciliation
block: a lockstep walk that would overwrite destination
list-2 nodes' payload slots from the source list 2; a destroy
loop (count decrement at +0x28, `_List_node_base::_M_unhook`
via PLT at 0x5f1296f, `operator delete(node, 0x18)` via PLT at
0x5f1297c) for surplus destination nodes if the source ran
out first; a second helper call at 0x5f12924 for the remaining
source range if the destination ran out first; and a closing
walk that increments every destination list-2 payload's +0x70
dword.

**List 2, as reachable.** The reconciliation's destination
cursor is `[destination + 0x18]`, reloaded at 0x5f128bd after
the list-1 helper call (or the header value outright on the
skipped-list-1 path through 0x5f12988). The prologue just
self-linked that header, and the helper writes only list 1 of
the destination, so the cursor is always the header itself:
the lockstep body never executes, the destroy loop never
destroys a node, and any nodes a caller had linked into the
destination list 2 beforehand are orphaned by the prologue --
neither overwritten, bumped, unlinked nor freed. What actually
runs on every call is the helper deep-copying the entire
source list 2 (raising +0x28 by the copied count), followed
by the closing payload bump. The packet's differential
verifies this byte-for-byte against the real bytes, including
cases with a preloaded destination list 2.

**Helper, by contract only.** 0x5f12320's body is not claimed
here. Its contract, read from its observable behaviour at the
call sites, is: deep-copy the source range [src_first,
src_header) -- fresh 0x18-byte node per source node, payload
qword copied, appended in order to the destination list whose
header is the second argument -- and add the copied count to
the qword at first_argument + 0x10. At both call sites in
this routine the first two arguments are the list's own base
(the object for list 1, object + 0x18 for list 2), so the
count that grows is that list's count field. The source list
is not modified; an empty range changes nothing.

**Exception exit.** The FDE's landing pad at 0x5f1299a
(`endbr64; mov %rax,%rbp; jmp 0x5f127f6`) is the body's only
other exit: the shared cleanup block at 0x5f127f6 raw-deletes
(size 0x18, no unhook) every node then in the destination
list 2, then every node then in list 1, and calls
`_Unwind_Resume`. The only calls in the body that can throw
are the two helper calls (the helper allocates). Exception
behaviour is pinned at this level only; the model and
differential cover non-throwing runs.

**Identity note.** The RE-002 vendor census identifies this
FDE as librocksdb-sys 0.11.0+8.1.1
`rocksdb::MemTableListVersion::MemTableListVersion(unsigned long*, const MemTableListVersion&)`
(340/358 bytes masked-equal against a published-crate
rebuild). That is RE-002's claim; it is consistent with
everything pinned here, and this packet neither needs nor
re-claims it.

## Consumers (site-only)

The census finds exactly one direct call site file-wide, no
tail jumps, no stored qwords and no RELATIVE addends:

- `0x5f13fca`, inside the copy-on-write prepare
  `0x5f13f90..0x5f13ff5` (mapped by RE-001-drain-driver-115).
  rdi is the fresh `operator_new(0x50)` object, rsi is
  `outer + 0x18`, rdx is the old inner object
  (`[outer + 0x08]`). The call runs before `[outer + 0x08]`
  is stored with the new pointer, before the init call to
  0x5f12a00 and before the tail jump into the release
  0x5f13ea0 on the old object.

## NOT claimed

The list-copy helper 0x5f12320's body (contract only, above)
and the neighbouring list-move function at 0x5f12320's own
landing area; what the copied +0x30 dword and +0x38 qword
mean to consumers of the object; what the payload +0x70 dword
counts beyond being the per-payload count this routine and
its pair increment; what a caller could make of the
unreachable lockstep/destroy paths (no caller can reach
them, since the prologue always runs first); behaviour when
allocation fails beyond the landing-pad level pinned above;
concurrent access (the payload increments are not atomic).

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5f12840 --stop-address=0x5f129a6 work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt text,
  never as a per-instruction list in records.json.
- `records.json`: semantic records only (the field writes and
  the never-written +0x34 dword, the phases with the
  reachability note, the helper contract, the landing pad,
  the census, the consumer, the closed unknown).
- `frames.txt`: FDE lines for the routine and its caller
  function. `callers.tsv`: the single direct call site with
  its enclosing caller FDE range. `relocations.txt` is
  empty: no relocation record mentions this routine.
- Census method: the external call census uses the exhaustive
  executable-segment E8/E9 scan with objdump confirmation per
  candidate; the single site was confirmed as a real
  `call 0x5f12840` instruction by direct dump. The routine's
  own control transfers are classified from one linear
  disassembly of the whole routine range (true instruction
  starts only): 4 internal direct calls (0x5f128b5 and
  0x5f12924 to the helper, 0x5f1296f and 0x5f1297c to PLT
  stubs), 1 internal direct tail jump (the landing pad's jump
  at 0x5f129a1 to the shared cleanup), no indirect transfers.
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run,
  every excerpt instruction byte-for-byte against the raw
  binary, spot instructions, the FDE ranges, the empty
  relocation set, the census, the records, and the model
  tests. `census.py` reproduces the census;
  `export_excerpts.py` regenerates `main.txt`.
- Model: `tools/cow_move_helper_12840_115.py`, tested by
  `tests/test_cow_move_helper_12840_115.py` (50 checks,
  including the prologue field set, the never-written +0x34
  dword, the self-copy guard, both list copies, payload
  counter wrap, and the preloaded-destination orphaning).
- Differential: `differential.py` runs the real 358 bytes
  under Unicorn against the model on 58 cases (structured
  list shapes, a self-copy, and randomised shapes), with the
  helper and the two PLT primitives answered by the same
  contract functions the model uses, comparing the whole
  object/node/payload window and heap window byte for byte,
  the allocator state, and the callee-saved registers: 0
  mismatches.

## Reproduce

Working directory: the repository root. Tools, all from this
run:

- GNU objdump (GNU Binutils for Ubuntu) 2.42, invoked as
  `objdump -d --start-address=0x5f12840 --stop-address=0x5f129a6 work/hl-node-115.bin`
- GNU readelf (GNU Binutils for Ubuntu) 2.42, invoked as
  `readelf --debug-dump=frames work/hl-node-115.bin` and
  `readelf -r work/hl-node-115.bin`
- Python 3.12.3 for `census.py`, `verify.py`,
  `export_excerpts.py`, and the model tests; the Unicorn
  differential additionally needs the `unicorn` package
  (2.1.4 used here).
- Input: `work/hl-node-115.bin`, SHA-256 as above; no
  execution of the target binary (the differential emulates
  the 358 routine bytes only, with the callee contracts
  stubbed), no network, no side effects beyond writing the
  packet files listed in MANIFEST.sha256.

## Verification scope and next step

This packet's own checker (`verify.py`), the model tests and
the Unicorn differential are run before submission and must
print ALL CHECKS PASSED, the model check count and
DIFFERENTIAL PASSED. Repository-wide gates (`make verify`,
`make test`, `make catalogue-check`) are run and reported
separately with the change. With this packet, both helpers
the drain-driver packet left by contract in the prepare are
pinned; the remaining by-contract item in that area is the
list-copy helper 0x5f12320's own body, which serves both this
routine and its own temp-list machinery and is a separate,
larger question.
