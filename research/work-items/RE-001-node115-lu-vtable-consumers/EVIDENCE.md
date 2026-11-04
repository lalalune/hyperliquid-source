# RE-001-node115-lu-vtable-consumers: which code consumes the lu.rs function-pointer slots

- Component ID: RE-001, `base/src/lu.rs` conversion callers (vtable consumers).
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream main
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (node-115-only migration).
- Claim status: observation for the two vtable layouts, the two
  consumers' clone/guard/worker-call flows, the once-closure shim route,
  the drop dispatcher's slot use, the twin drops' tag-shift template, and
  all census counts; inference for the "trait object" reading of the
  (data, vtable) pairs (from the vtable layout plus the dispatcher's
  slot-0 call and size/align deallocation, not from a symbol name);
  unresolved for the Rust type/trait names, the final `[vtable+0x18]`
  method invocation, the Q table's `+0x8` slot, the once record's full
  semantics, the format/parse call, the forwarding shim, the caller-2
  consumer's direct caller, and the worker's full body.
- Scope included and excluded: included — consumer `0x15d6230..0x15d6310`
  (224B, 58 instructions), consumer `0x15d2fb0..0x15d31c7` (535B, 126
  instructions), drop dispatcher `0x15dacd0..0x15dad33` (99B, 35
  instructions), drop twins `0x15e04b0..0x15e0537` and
  `0x15d9ca0..0x15d9d27` (135B, 40 instructions each); the two vtables
  (32 bytes each) with their following Location structs; GOT and
  Location resolutions; full census counts. Excluded — #183's conversion
  body, #184's helper body, and #185's coop callee and proceed function
  (cited, not re-claimed); the worker body (context only, handoff facts
  observed); the indirect consumers of the Q table's `+0x8` slot.

## Reproduce

Working directory: the repository worktree at the base commit above.
Inputs: `artifacts/node/115/hl-node` (digest above). Tools: GNU objdump
(`objdump -d -M intel --start-address=.. --stop-address=..`), Python 3
with `struct`/`re` for the relocation and census scans, and the tree's
`tools/fde_extents.py` for FDE ranges. No execution of the node binary,
no network, no disassembler database: all analysis is static byte and
disassembly reading. Deterministic: the verifier
`tools/node115_lu_vtable_consumers.py` re-checks the digest, all five
body hashes and pinned hex files, both vtable records with their
following Locations, all 5 GOT resolutions, all 4 `lea` sites (and the
zero `lea` sites to the fn slots), all 7 `E8` census counts, and the
twin mnemonic-sequence equality, and exits 0. Declared side effects:
none (read-only).

## Evidence

Original addresses are ELF virtual addresses (PIE). `.text` file offset =
VA − 0x1000; `.data.rel.ro`/`.got` file offset = VA − 0x2000; `.rodata`
file offset = VA. Validated boundaries (all CIE `0x103d604`):
consumer-caller2 FDE `.eh_frame` offset `0x3b4240`, LSDA `0x182450`,
range `0x15d6230..0x15d6310`; consumer-statemachine FDE offset
`0x3b3f64`, LSDA `0x1821c0`, range `0x15d2fb0..0x15d31c7`;
drop-dispatch FDE offset `0x3b4eec`, LSDA `0x182e44`, range
`0x15dacd0..0x15dad33`; drop-caller2 FDE offset `0x3b69e0`, LSDA
`0x183d0c`, range `0x15e04b0..0x15e0537`; drop-statemachine FDE offset
`0x3b49e8`, LSDA `0x182ba0`, range `0x15d9ca0..0x15d9d27`. Raw
disassembly and bytes are beside this record (`*.objdump.txt`,
`*.hex`); structured records (vtables, Locations, GOT, census, worker
handoff, open points) are in `records.json`. Callers/callees/indirect
calls: caller-2 vtable 2 `lea` sites (both in consumer `0x15d6230`) /
0 `lea` to the fn slot; state-machine vtable 2 `lea` sites (both in
consumer `0x15d2fb0`) / 0 `lea` to the fn slot; consumer-statemachine
1 direct `E8` caller (the shim); consumer-caller2 1 direct `E8` caller
(site `0x1534f75`); drop twins 1 direct `E8` caller each (their
consumers' landing pads); drop dispatcher 25 raw `E8` sites; worker 24
raw `E8` sites. Source mapping evidence: the two `lu.rs` Location
records resolved through RELATIVE addends (file slots zero, file string
`base/src/lu.rs` at `0x4326c1`, lengths 14, lines/columns 159:64 and
220:26); the once.rs Location (159:50) in the `0x6401200` record is
read the same way. ABI/layout observations: vtable = (drop fn, size,
align, method fn); drop dispatcher = slot-0 call then (size, align)
deallocation; twin drops = tag-3 gate, refcount `lock dec`, tag-selected
drop helper, tail jump to `0x15df190`; worker call shape = (arg1, arg2,
1, clone, vtable). Analysis was complete over the five claimed FDEs,
the two vtables, and the census scans; it was not a whole-binary
disassembly. The 4,840 raw `[reg+0x18]` sites were counted by byte
scan and deliberately not attributed to these vtables.

## Implementation and comparison

No Rust reimplementation is included: this packet is static research
only, and no component gate is requested. No prior packet's bytes are
re-claimed: #183's conversion, state machine, caller-2, and guard
bodies, #184's helper body, and #185's coop callee and proceed bodies
are cited for the chain and explicitly excluded from the claim set.
The worker body is likewise cited as context from #183/#185, not
claimed. The only overlap with prior packets is by citation: the
vtable method slots name #183's functions, and the drop helpers
`0x5ce8da0`/`0x5ce86d0` are the same two #183's conversion drop path
uses — both facts are stated as shared machinery, not as new claims.

## Limitations and next step

The final `[vtable+0x18]` method invocation is not identified for these
two vtables (4,840 raw sites, none statically linked); the Q table's
slot `+0x8` is not answered; the once record, the format/parse call,
the forwarding shim, the caller-2 consumer's direct caller, and the
worker body are not decoded. Next question: what the Q table's slot
`+0x8` calls, which needs a static Q-table instance or a coop-site Q
construction trace.
