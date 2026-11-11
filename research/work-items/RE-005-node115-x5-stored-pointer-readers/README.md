# RE-005 node 115: who reads the X5 callers' stored pointers

## Question

The consumer-callers packet (`RE-005-node115-x5-consumer-callers`)
pinned the 65 FDE bodies that call the 63 consumers of GOT slot
`0x64e7718` directly, and recorded one level up as counts only.
Seven of those caller bodies have no direct rel32 caller at all;
each is reached only through exactly one `.rela.dyn` entry whose
addend is the body start -- a stored pointer in `.data.rel.ro`.
That packet counted the seven stored pointers and did not follow
them. Who reads them -- at which reference sites, in which bodies,
and in what use form?

## Method

Static analysis only, against the authenticated node 115 binary
(SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`). Each stored body's
defining relocation is re-derived from the binary (exactly one
entry, `R_X86_64_RELATIVE`, addend == body start, slot in
`.data.rel.ro`). Every rip-relative reference to each slot is
enumerated with a disp32 candidate scan over every executable
section (.fini, .init, .plt, .text), each candidate
verified by decoding the instruction at the site, and each
verified site cross-checked against a linear disassembly sweep of
its containing FDE body. For slots with no direct reference, the
vtable header in the 0x18 bytes before the slot is validated
(a relocation at the header base whose addend is an FDE body
start -- the drop entry -- followed by the size and align qwords),
and every rip-relative reference to the header base is enumerated
the same way. Each reference site's use of the materialised base
is classified by forward register tracking inside its body.
Independent passes excluded the other forms for all seven slots
and five bases: relocation addends across all
60723 `.rela.dyn` and 278
`.rela.plt` entries, stored 8-byte copies outside the relocation
sections' own serialised entries, immediate materialisations, and
`.dynsym` values.

## Answer

Every stored pointer has exactly one reader, and the seven
readers are seven distinct bodies with one `lea` reference site
each:

- body `0x159d600` (5303 bytes), slot `0x63ff748` (header base 0x63ff730: drop 0x15a9c50, size 3744, align 8); method run 1; reader body `0x15d0660`, `lea` at `0x15d089d` (materialise_into_constructed_record)
- body `0x17457f0` (10479 bytes), slot `0x640e920` (header base 0x640e908: drop 0x174d9c0, size 3744, align 8); method run 1; reader body `0x16d7df0`, `lea` at `0x16d8171` (materialise_into_constructed_record)
- body `0x2a225c0` (3471 bytes), slot `0x64455e0` (header base 0x64455c8: drop 0x29eadd0, size 2208, align 16); method run 1; reader body `0x2d062f0`, `lea` at `0x2d06804` (store_and_direct_dispatch)
- body `0x2a2a0e0` (6050 bytes), slot `0x6445880` (header base 0x6445868: drop 0x29ea680, size 2224, align 16); method run 1; reader body `0x2d087e0`, `lea` at `0x2d090a2` (store_and_direct_dispatch)
- body `0x2a64e20` (5380 bytes), slot `0x64462b0` (header base 0x6446298: drop 0x2aa31b0, size 3744, align 8); method run 1; reader body `0x294f1a0`, `lea` at `0x294f3dd` (materialise_into_constructed_record)
- body `0x5a93b50` (1387 bytes), slot `0x64b9b70` (slot is its own base; preceding triple 0xd38, 0x20, 0x28); method run 7; reader body `0x5964ef0`, `lea` at `0x5964f64` (materialise_into_constructed_record)
- body `0x5a940c0` (1343 bytes), slot `0x64ba390` (slot is its own base; preceding triple 0x58, 0x20, 0x30); method run 7; reader body `0x5965d90`, `lea` at `0x5965e04` (materialise_into_constructed_record)

Two slots are their own vtable base -- the reader loads the slot
address itself (`0x64b9b70` read by body `0x5964ef0`, `0x64ba390`
by body `0x5965d90`), and each begins a run of seven consecutive
code entries. The other five slots are the first -- and only --
code entry of a vtable whose {drop, size, align} header
occupies the 0x18 bytes before the slot (the entry after each of
the five points into `.rodata`), and the reader loads the header
address.

The uses separate into two forms:

- **Materialise into a constructed record
  (5 readers)** -- the base is
  stored into a record the reader builds on the stack: at field
  offset 0x10 of a 0x200-byte record for the two slot-base
  readers, and at field offset 0x30 of a 0x128-byte record for
  three header-form readers (bodies `0x15d0660`, `0x16d7df0`,
  `0x294f1a0`). The record is then copied into a fresh allocation.
- **Store and direct dispatch
  (2 readers)** -- bodies
  `0x2d062f0` and `0x2d087e0` store the header base into an object
  field at +0x70 and immediately read the stored pointer back:
  `call qword ptr [rax + 0x18]`, whose effective address is the
  slot itself. These two bodies call exactly the stored bodies
  `0x2a225c0` and `0x2a2a0e0` through their slots.

No other path exists: no relocation addend, no stored 8-byte
copy, no immediate materialisation, and no dynamic symbol names
any of the seven slots or five bases (the exclusion census is
zero in every form).

One level up is recorded as counts only (`direct_callers` and
`relocation_addends` per reader body).

## Boundaries

RE-011-evm-permit-routing-115 records two of the seven (reader body, base, stored body) triples as method-table rows -- future body 0x2d087e0 with inner vtable 0x6445868 and inner poll target 0x2a2a0e0 (eth_call), and future body 0x2d062f0 with inner vtable 0x64455c8 and inner poll target 0x2a225c0 (eth_estimateGas) -- without reference sites, use forms, or a completeness census. RE-011-eth-call-path-115, RE-001-node115-channel-repoll-terminal and RE-003-pr-integration-20261103 mention individual body or slot addresses incidentally.  The source packet (RE-005-node115-x5-consumer-callers) counted the seven stored pointers and left their readers as an explicit boundary; no earlier packet enumerates the readers of all seven, pins their reference sites and use forms, or excludes the other reference forms for the slots and bases.

For each reader body this packet records only two counts: raw direct rel32 call/jump byte occurrences in .text whose target is the body start, and .rela.dyn entries whose addend is the body start.  The reader bodies' own callers are outside this packet's question.

Once a constructed record carrying a vtable base leaves its constructor, later reads of the method entry go through that record's vtable field generically (a load of the field at +0x18 for the header form, or at +0x0 for the slot-base form); those dispatch sites are shared by every vtable of the same shape and are not attributable to one slot by static evidence.

Which runtime path reaches a given reader, what the per-slot statics name, and the concrete Rust types of the stored and reader bodies are not established by static evidence.
