# RE-005 node 115: is the wake action ever dispatched through the wake vtable's +0x20 (call_mut) slot

Packet type: static evidence (target-bound). Continues
RE-005-node115-signal-sv1-writer (PR #2974), which pinned the
registration chain and the handler's dispatch but left one edge
undecided: the signal-delivery handler os_handler 0x5c67560 is
observed dispatching the registered per-signal action through
slot +0x28 of the wake vtable 0x64c54b8 only. The vtable's slots
are +0x18 (call_once) → wake_call_once 0x5cdd040, +0x20 →
wake_call 0x5cdcda0, +0x28 → wake_call 0x5cdcda0. Because +0x20
and +0x28 hold the same body, the wake behaviour is identical
either way; what is at stake is the exactness of the dispatch
pin — which calling convention the action is invoked through.

## Question

Is there any reachable path in the artifact that dispatches a
registered wake action through the vtable's +0x20 slot (the
FnMut::call_mut position), instead of or in addition to the
+0x28 slot (the Fn::call position) the handler uses?

## Answer

**No. The +0x28 slot is the only dispatch slot ever used for
this vtable, and the +0x20 slot is never read by any reachable
path.** Every link is pinned in records.json and re-derived by
tools/wake_vtable_callmut_static.py:

1. **The vtable address has exactly one source.** A whole-.text
   census of REX.W `lea` with a RIP-relative target finds the
   address 0x64c54b8 materialised at exactly five sites —
   0x5cdd54f, 0x5cdd568, 0x5cdd5df, 0x5cdd695, 0x5cdd874 — all
   inside registry_insert 0x5cdd480, where it is stored into the
   trait-object fat pointers being built. The address occurs
   zero times as a qword anywhere in the file image and zero
   times as a relocation addend (evidence:
   registry_insert_vtable_leas.objdump.txt, vtable_slots.txt).
2. **The registry global has exactly three genuine consumers.**
   Decoding every body that a raw disp32-window scan nominates
   as a candidate referencer of the registry region
   (0x64fff50..0x64fffb8) leaves exactly five bodies with
   genuine RIP-relative references: os_handler (fields +0x00,
   +0x18, +0x20, +0x40, +0x48 of the struct at 0x64fff58), the
   registry constructor 0x5c67aa0, and entry_init 0x5cdbf20.
   Two further bodies (0x5c4e240, 0x14353b0) reference only the
   neighbouring word 0x64fff50 below the struct and contain no
   indirect call at all. Thirteen candidate bodies are
   byte-pattern phantoms — no genuine reference on decode;
   they are enumerated in records.json
   (`registry_global.phantom_bodies`). registry_insert and
   entry_lookup receive their table pointers as arguments and
   reference no globals; both are inventoried anyway.
3. **The cluster's indirect-call inventory contains exactly
   one vtable-slot dispatch.** Over the eighteen cluster
   bodies (handler, constructor and its helpers/shim,
   entry_init, registry_insert, entry_lookup, the raw-table
   insert helper, io_error_ctor, the OnceLock/entry shims, the
   send helper, both wake shims, both neighbour bodies):
   disp-0x18 sites 0, disp-0x20 sites 0, disp-0x28 sites
   exactly 1 — os_handler 0x5c67834 `call *0x28(%rax)`, byte
   pin `ff5028`. The seven register-indirect sites are all
   classified non-vtable calls: four previous-handler raw
   function-pointer calls in os_handler (values loaded from
   the per-signal record, gated by a `cmp $0x2` check against
   the SIG_DFL/SIG_IGN sentinels), sched_yield through its
   GOT slot in entry_init's spin-wait (0x5cdc510; slot
   0x64e1558, GLOB_DAT, dynsym `sched_yield`), memmove
   through its GOT slot in registry_insert (0x5cdde42; slot
   0x64df568, GLOB_DAT, dynsym `memmove`), and the drop slot
   of an unrelated boxed-error trait object in io_error_ctor
   (0x5cdd2c1; target loaded from the object's own vtable
   base, offset 0). The raw-table insert helper's single
   slot call is through the table's own hasher field at
   +0x30 (0x5cde904), not through any action vtable.
4. **Inside the handler, the vtable register is touched
   exactly twice.** os_handler loads the element's vtable
   word from the bucket (`mov 0xb8(%rdx,%rax),%rax` at
   0x5c67813) and dereferences it only at +0x10 — the align
   field, a data read feeding the environment-pointer
   arithmetic (`mov 0x10(%rax),%rdx` at 0x5c6781b) — and at
   the +0x28 call. There is no +0x20 read in the loop
   (evidence: os_handler_dispatch.objdump.txt).

Whole-.text context (decoded census, evidence
census_decoded.json): 5,184 disp-0x20 call/jmp sites in 2,141
bodies, 4,754 disp-0x18 sites in 2,773 bodies, 350 disp-0x28
sites in 281 bodies, 72,638 register-indirect sites in 31,689
bodies. A disp-0x20 site can dispatch this vtable only if its
base register holds 0x64c54b8; by (1) and (2) that value
reaches a register only as registry_insert's stored lea
result (never dereferenced there) or as os_handler's element
load (dereferenced only per (4)). None of the 5,184 sites is
in a body that references the registry global or in any
cluster body.

The same inventory also shows the +0x18 (call_once) slot is
never dispatched from any cluster body; wake_call_once is
reachable only as a vtable entry, exactly as #2974 left it.

## Boundary

The vtable +0x00 drop slot has file value 0 and no
relocation; its run-time value is established by the dynamic
loader and is not statically claimable. This packet does not
touch it. The finding is a dispatch-convention pin: since
+0x20 and +0x28 name the same body, no behavioural claim
changes — the registered action is invoked exclusively
through the Fn::call slot with the shared-reference
convention, never through FnMut::call_mut.

## Files

- records.json — every pin, re-derived by
  tools/wake_vtable_callmut_static.py `analyze()` (the test
  asserts byte-for-byte equality with a fresh run).
- census_decoded.json — the decoded whole-.text census
  (method stated inside).
- os_handler_dispatch.objdump.txt — the action loop and
  previous-handler call contexts.
- registry_insert_vtable_leas.objdump.txt — the five lea
  materialisations.
- entry_init_sched_yield.objdump.txt — the spin-wait whose
  only register-indirect call is sched_yield.
- io_error_ctor_drop.objdump.txt — the boxed-error drop call.
- raw_table_insert_fn.objdump.txt — the generic raw-table
  helper and its +0x30 hasher-field call.
- vtable_slots.txt — the vtable's file qwords and
  relocations.
