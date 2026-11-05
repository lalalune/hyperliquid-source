# RE-001: node #115 stats-emit caller 0x5d7dfc0

- Component ID: RE-001 (node #115 function map)
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json, `artifacts/node/115/hl-node`; local copy
  `work/hl-node-115.bin` hashes exactly)
- Source commit / reference commit: upstream main `05bc2de30`
- Claim status: observation for everything below except the items listed
  under Unknowns, which are inference boundaries, not claims.

## Bounded question

What does the sole caller of the stats-emit routine 0x5d52020 do
end to end: how does it walk the version list, what per-version
work does it do, what does it emit, and what does it clean up?

## Answer, pinned to the target

The routine takes one object pointer in `rdi` and returns void.
It is the DB dump entry behind the `db/db_impl/db_impl.cc`
format strings at lines 1084-1093. In order:

1. **Skip flag.** When the byte at object `+0x17b4` is nonzero,
   the routine disposes the (still empty) dump string and returns
   at once: no lock, no walk, no emit, no stats-emit call.
2. **Setup.** It builds an empty SSO dump string at `rsp+0x70`
   (inline buffer at `rsp+0x80`) and a stack hash table at
   `rsp+0x30`: single bucket at `rsp+0x60`, bucket count 1,
   element count 0, max load factor `1.0f` at `rsp+0x50`. The
   single-bucket address is saved at `rsp+0x10` for the cleanup
   decision. The mutex pointer (`obj+0x700`) is saved at `(%rsp)`
   and the dump-string address at `rsp+0x08`.
3. **Lock.** Call the instrumented acquire `0x606ca40` on
   `obj+0x700` (pinned whole in its own packet; re-shipped here).
4. **Version walk (phase 1).** The list head is
   `*(*(*(obj+0x68)+0x40)+0x110)`; links are the `+0x938` fields
   of a circular list whose head is that node. A node's `+0x00`
   u32 is compared against the sentinel `0xffffffff` (rodata word
   at `0x96db54`); its refcount is the s32 at `+0x38`; its flag
   byte is at `+0x3c`. Entry bumps the first node's refcount (and
   the head's, reloaded) when the marker differs from the
   sentinel. The loop ends when the cursor returns to the head.
   For each node whose flag byte is clear, the routine advances
   without touching it. For each flagged node it unlocks the
   mutex, calls the refresh callee `0x5eef8a0` with
   `(node+0x8d8, 0)`, and — when the sink at `obj+0x360` is
   non-null — builds the `"BlockCache"` string, calls the virtual
   slot `+0x38` of the object at `node+0x620` with
   `(that object, &"BlockCache" string)`, disposes the string, and
   when the produce call returns a non-null key, inserts the key
   pointer into the hash table. On a first sight of a key it
   reads the key's vtable slot `+0xd0` and, unless that slot
   equals the identity function `0x5d3a940` (installed by the
   RELATIVE relocation at `0x64ecd10`), calls it with
   `(key, sink at obj+0x360)`. A repeated key is a dedup hit: no
   second dispatch. Then it re-locks the mutex and advances.
   Advancing releases the old node (call `0x5d911e0`) when its
   marker differs from the sentinel, moves to the `+0x938` next
   node, and bumps the next node's refcount when its marker
   differs. On loop exit the head is released while its marker
   differs, re-tested after each call (the binary shows at most
   two calls; see Unknowns).
5. **Registry factories (phase 2).** The routine copies the BSS
   `{ptr, len}` slice at `0x65030e0` to `rsp+0x20`, looks it up
   with `0x5eee790`, and invokes the result with `0x5eee9f0`
   using `(obj+0x748, entry, &slice, &dump-string)`. It then
   copies the BSS slice at `0x6502a80`, looks it up the same
   way, and invokes that entry once per flagged version node
   with `(node+0x8d8, entry, &slice, &dump-string)`. Both BSS
   slices' bytes are not in the file; only the access pattern is
   pinned. The lookup trims trailing ASCII digits from the name
   before matching; the invoke trims them again and tail-jumps
   to the factory selected from the entry (see the callee notes).
6. **Dump emits (phase 3).** It unlocks the mutex, then calls the
   log dispatcher `0x5fcf060` twice at level 1 with the sink at
   `obj+0x360` by address and the file `"db/db_impl/db_impl.cc"`:
   first `"[%s:1084] ------- DUMPING STATS -------"` (whose `%s`
   is the file name), then `"[%s:1086] %s"` with the accumulated
   dump string as the second `%s`.
7. **Malloc-stats branch.** When the byte at `obj+0x4c1` is
   nonzero, it truncates the dump string to empty and calls the
   hook `0x5f04ce0` with `&dump-string`. The hook in this binary
   is a 5-byte no-op (`endbr64; ret`), so the string stays empty
   and the branch falls through. When the hook fills the string
   (not observable in this binary), the routine emits
   `"[%s:1091] ------- Malloc STATS -------"` and
   `"[%s:1093] %s"` with the filled string, then continues.
8. **Stats emit.** Call `0x5d52020` with the object (pinned whole
   in its own packet; re-shipped here): it gates on `obj+0x548`,
   produces via vtable slot `0xe8`, and emits
   `"[%s:774] STATISTICS:\n %s"`.
9. **Cleanup.** Free every 16-byte hash node through the
   before-begin chain (`operator delete` with size `0x10`),
   `memset` the bucket array to zero, delete the bucket array
   only when it is not the inline single-bucket slot, reset the
   count and the chain head, dispose the dump string, check the
   stack canary, and return.

The seven landing pads at the end of the routine
(`0x5d7e5d3..0x5d7e627`) jump into the shared cleanup fragment
`0x5d7dede..0x5d7dfba` (its own FDE), which repeats the head
release, the mutex unlock, the hash-node free, the bucket
`memset` and delete, the string dispose, and the canary check,
then `_Unwind_Resume`. The fragment is pinned whole.

## Callees pinned whole in this packet

| address | FDE range | size | what it is |
| --- | --- | --- | --- |
| 0x5d7dfc0 | 0x5d7dfc0..0x5d7e627 | 2151 B | the routine itself |
| 0x5d7dede | 0x5d7dede..0x5d7dfba | 220 B | shared cleanup fragment |
| 0x5d4ab80 | 0x5d4ab80..0x5d4ac63 | 227 B | std::string assign from a C string |
| 0x5d911e0 | 0x5d911e0..0x5d912a3 | 195 B | version refcount release |
| 0x60d52f0 | 0x60d52f0..0x60d5385 | 149 B | mutex-unlock wrapper |
| 0x5f04ce0 | 0x5f04ce0..0x5f04ce5 | 5 B | no-op hook (endbr64; ret) |
| 0x5d3a940 | 0x5d3a940..0x5d3a945 | 5 B | identity function (endbr64; ret) |
| 0x5fcf060 | 0x5fcf060..0x5fcf153 | 243 B | level-gated log dispatch |
| 0x5eee790 | 0x5eee790..0x5eee9e7 | 599 B | registry lookup by trimmed name |
| 0x5eee9f0 | 0x5eee9f0..0x5eeea59 | 105 B | trim trailing digits, tail-jump to factory |
| 0x606ca40 | 0x606ca40..0x606cc6a | 554 B | instrumented acquire (re-shipped) |
| 0x5d52020 | 0x5d52020..0x5d520c1 | 161 B | stats emit (re-shipped) |

The acquire and stats-emit excerpts are re-shipped from their
own packets (`RE-001-instrumented-acquire-6ca40-115/main.txt`,
`RE-001-stats-emit-52020-115/main.txt`) so this packet verifies
standalone: every instruction line is byte-identical to the
source packet's excerpt (diffed); only the objdump header line
differs (relative vs absolute invocation path).

## Callee notes (pinned semantics)

- **0x5d4ab80 string assign** (`rdi=&string, rsi=C string`):
  `strlen`, SSO copy inline for length <= 15 (including the
  NUL at the inline buffer), `_M_create` + `memcpy` above;
  throws `__throw_logic_error` with
  `"basic_string: construction from null is not valid"` (string
  at `0x963298`, verified in the raw binary) when the C string
  is null.
- **0x5d911e0 version release** (`rdi=node`): `lock xadd -1`
  to the refcount at `+0x38`. Old value 1: full teardown via
  `0x5d8fef0`, then sized delete `0x9e8`; returns 1. Old value
  2: unlink the `+0x920`/`+0x930` pair (both zeroed), delete the
  `+0x930` object via `0x61d3c90` + sized delete 4, then when
  `0x5d8bc70` returns true call `0x5d910e0` and `0x5d8d820`
  and sized-delete `0x290`; returns 1 when that path frees,
  0 otherwise. Any other old value: return 0. The sub-callees
  stay opaque.
- **0x60d52f0 mutex unlock** (`rdi=mutex`): `pthread_mutex_unlock`;
  returns silently for status 0, `0x10` or `0x6e` (110);
  otherwise prints `"pthread %s: %s\n"` with `"unlock"` (format
  at `0x43742f`, word at `0x43948f`, both verified in the raw
  binary) to the stderr object at `0x64edcb8`, disposes a string
  and aborts.
- **0x5fcf060 log dispatch**
  (`edi=level, rsi=&sink, rdx=format, rcx=file, r8/r9=varargs`):
  builds a `va_list` whose varargs are `(file, r8, r9, ...)`
  (`gp_offset` 0x18, register save area at `rsp+0x20`). When
  the sink pointer is null it returns at once. It reads the
  level gate from vtable slot `+0x40` of the sink object and
  returns without logging when `level` exceeds it. Level 5 goes
  to slot `+0x18` (`(sink, format, va_list)`); every other
  admitted level goes to slot `+0x28`
  (`(sink, level, format, va_list)`).
- **0x5eee790 registry lookup** (`rdi=&{ptr, len}` slice):
  trims trailing ASCII digits from the slice, then looks the
  trimmed name up in the registry object at `0x6502a40`. When
  the registry's `+0x18` field is at most `0x14` it walks a
  linked list comparing `(length, memcmp)`; above that it hashes
  with `_Hash_bytes` and seed `0xc70f6907`, divides by the
  bucket count at `+0x08`, and walks the bucket chain comparing
  the stored hash at node `+0x70`, the length at `+0x10` and
  the bytes. Returns the matched node's `+0x28` slot, or 0 on a
  miss.
- **0x5eee9f0 trim and invoke**
  (`rdi=obj, rsi=entry, rdx=&slice, rcx=&dump-string`): counts
  the slice's trailing ASCII digits, then tail-jumps to the
  factory. The target is the entry's `+0x08` slot when its low
  bit is clear; when set, it is loaded from
  `*(*(obj + entry+0x10) + entry+0x08 - 1)`. At the jump:
  `rdi = obj + entry+0x10`, `rsi = &dump-string`,
  `rdx = trimmed end pointer`, `rcx = trailing-digit count`.
- **0x5f04ce0 / 0x5d3a940**: five bytes each, `endbr64; ret` —
  genuine instructions in the target binary, not placeholders.
  The first is the malloc-stats hook; the second is the identity
  function the slot `+0xd0` dispatch is compared against.

## Opaque callees (call-site contract pinned, internals not)

- **0x5eef8a0 refresh** (`rdi=node+0x8d8, rsi=0`), FDE
  `0x5eef8a0..0x5eefd49` (1193 bytes), 3 direct calls
  (0x5d7e0d7 here, 0x5ef03d5, 0x5ef9565): locks the node's mutex,
  walks a handler chain, copies a large stats snapshot under the
  lock. A separate work item should pin its internals.
- **0x5d7dda0 rehash helper**
  (`rdi=&table, rsi=new size, rdx=&rehash state`), FDE
  `0x5d7dda0..0x5d7dedd` (4413 bytes), 1 direct call (0x5d7e582):
  the libstdc++ `_Hashtable::_M_rehash_aux`. Not modelled
  internally; the model records the rehash trace.
- PLT calls: `operator new` / `operator delete` (sized),
  `memset`, `_M_dispose`, `_M_need_rehash`,
  `__stack_chk_fail`, `_Unwind_Resume`.

## Consumers

The routine itself has 0 direct calls and exactly 1 tail jump:

- `0x5d7e63a`, inside the 15-byte forwarding thunk FDE
  `0x5d7e630..0x5d7e63f` (`endbr64; mov (%rdi),%rax; mov
  (%rax),%rdi; jmp 0x5d7dfc0`), pinned whole as
  `site-5d7e63a.txt`. The thunk double-dereferences its argument
  and tail-jumps into the routine.

Callee consumer counts (executable-LOAD-segment exhaustive
E8/E9 scan with objdump confirmation, reproduced by `census.py`
and re-run inside `verify.py`): string assign 35 direct calls;
version release 53 direct calls + 1 tail jump; mutex unlock 669
direct calls + 5 tail jumps; log dispatch 252 direct calls + 1
tail jump; registry lookup 6 direct calls (0x5d4dc23,
0x5d63c2f, 0x5d63e3a, 0x5d63f02, 0x5d7e221, 0x5d7e26b — the last
two are the two lookups in this routine); trim invoke 3 direct
calls (0x5d63d20, 0x5d7e249, 0x5d7e2c9) + 1 tail jump; refresh 3
direct calls (0x5d7e0d7, 0x5ef03d5, 0x5ef9565); acquire 244
direct calls + 8 tail jumps; stats emit 1 direct call
(0x5d7e339, here); noop hook 1 direct call (0x5d7e456, here);
identity 0 direct calls and 0 tail jumps — reached only through
data: 8 RELATIVE records install it (0x64c8980, 0x64c8a88,
0x64c8c18, 0x64c8d30, 0x64c8e70, 0x64c8f70, 0x64c9ed0, 0x64ecd10);
the one this routine's slot `+0xd0` guard reads is `0x64ecd10`.
Its 8 stored qwords are exactly those 8 RELATIVE addends in
`.rela.dyn` (verified entry by entry); no other pinned routine
has stored qwords or RELATIVE addends. The walker global at
`0x64ecf80` (RELATIVE addend `0x5d4d490`) is context for the
refresh callee, not this packet.

The routine's own control transfers: 28 direct calls, 7 direct
tail jumps (all seven landing pads into the cleanup fragment),
2 indirect calls (slot `+0x38` at `0x5d7e111`, slot `+0xd0` at
`0x5d7e56b`), 0 indirect tail jumps. The cleanup fragment's own
transfers: 12 direct calls, 0 tail jumps, 0 indirect calls,
0 indirect tail jumps.

## NOT claimed

What the virtual produce callee behind slot `0xe8` in the
stats-emit routine computes (the object at `+0x548` is never
written by this routine); what the slot `+0x38` produce callee
or the slot `+0xd0` dispatch callee compute; what the fields at
`+0x548`, `+0x360`, `+0x68`, `+0x700`, `+0x748`, `+0x17b4` or
`+0x4c1` denote beyond their offsets; the contents of the BSS
slices at `0x65030e0` and `0x6502a80`; the refresh callee's
internals; the rehash helper's internals; the exact
`_M_need_rehash` trigger formula (the model uses the call shape
`(element_count, bucket_count, 1)` with the libstdc++ prime
policy as an inference); why the head release runs twice when
its marker differs (recorded branch shape, rationale unknown);
behaviour on a null owner object (the routine reads `+0x17b4`
unconditionally, so the model raises on a null object, stated
openly).

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`, `cleanup.txt`, `string_assign.txt`,
  `version_release.txt`, `mutex_unlock.txt`, `noop_hook.txt`,
  `identity.txt`, `log_dispatch.txt`, `registry_lookup.txt`,
  `trim_invoke.txt`, `acquire.txt`, `stats_emit.txt`: whole-function
  verbatim excerpts, produced by `export_excerpts.py`.
  Instruction-level detail lives only in these excerpt texts,
  not in `records.json`, which carries semantic records only.
  Mnemonics in the excerpts (including `endbr64` at routine
  entries and at landing-pad entries) are genuine instructions
  present in the target binary, not placeholders; `verify.py`
  checks every excerpt instruction byte-for-byte against the
  raw binary and against a fresh objdump run.
- `site-5d7e63a.txt`: the forwarding thunk, verbatim.
- `frames.txt`: the FDE lines for the routine, the cleanup
  fragment, every pinned callee, and the thunk, from
  `readelf --debug-dump=frames`.
- `callers.tsv`: every confirmed direct call and tail-jump site
  for every pinned routine, with the caller FDE range,
  reproduced by `census.py`.
- `relocations.txt`: the RELATIVE records that mention a pinned
  routine (8 records install the identity function `0x5d3a940`).
- `records.json`: semantic records only (phases, gates, formats,
  census counts, internal transfer lists).
- `verify.py`, `export_excerpts.py`, `census.py`: the packet's
  own runnable checkers, committed in the packet.
- Model: `tools/stats_emit_caller_7dfc0_115.py`; tests:
  `tests/test_stats_emit_caller_7dfc0_115.py` (20 checks).

## Reproduce

From the repository root, with GNU objdump/readelf (Binutils
2.42) and Python 3.12.3:

- `python3 research/work-items/RE-001-stats-emit-caller-7dfc0-115/export_excerpts.py`
- `python3 research/work-items/RE-001-stats-emit-caller-7dfc0-115/census.py`
- `python3 research/work-items/RE-001-stats-emit-caller-7dfc0-115/verify.py`
- `python3 tests/test_stats_emit_caller_7dfc0_115.py`

Repository-wide gates (`make verify`, `make test`,
`make catalogue-check`) are not claimed here: the baseline on
this machine is affected by missing LFS material and by the
absence of cargo/rustc, and this packet changes no
repository-wide behaviour. Only this packet's checker and the
model tests are claimed.

## Next step

- Pin the refresh callee `0x5eef8a0` whole (1193 bytes, 3
  callers): its mutex discipline, handler-chain walk and stats
  snapshot copy are a bounded work item of their own.
- Resolve the virtual produce callee behind slot `0xe8` in the
  stats-emit routine: find what writes the object at `+0x548`
  and which vtable it carries.
- Pin the rehash helper `0x5d7dda0` only if a work item needs
  its exact growth behaviour; the call-site contract here is
  enough for the dump routine.
- The owning caller functions `0x5d6da20..0x5d6ee3c` and
  `0x5d6ef60..0x5d6faa0` (the sort entry's callers), the
  flag-nonzero insert callee `0x606ef50`, the `0x5d4ed40` /
  `0x5d4f400` map routines, and the owning callers
  `0x5d8479c..0x5d85475` / `0x5d878f0..0x5d887b0` remain
  undecomposed; which of the 252 acquire callers pass type code
  `0x34` versus other codes is still an open census question.
