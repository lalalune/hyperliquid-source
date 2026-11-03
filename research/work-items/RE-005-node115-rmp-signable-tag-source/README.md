# RE-005: node 115 `rmp_signable` tag sources — who writes the two tag source bytes one level above the chain top

- Component ID: `serialization` (RE-005, Serialization/signing:
  `bincode_fork/*`, `l1/action/rmp_signable.rs`).
- Target release and full SHA-256: node #115, Linux x86-64, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`;
  no submodule commit is changed by this packet.
- Claim status: **observation** for both one-level writer traces below,
  all re-derived from the pinned target bytes by the checker;
  **unresolved** for every naming or semantic claim listed under the
  boundary.

## The bounded question

The chain-top packet (RE-005-node115-rmp-signable-chain-top)
established that on the grand_a path the serializer tag is the byte
at the address stored in the cell the top FDE's container field
+0x10 points to, and on the grand_b path it is the byte at
`[arg2+0x11d]` of the record the grand_b_caller FDE receives — and
left open what those source bytes denote and which values they
take. This packet traces both source bytes exactly one level
higher: who establishes the records the two reaching FDEs consume,
and which instruction writes each source byte there.

## Why this item

The operator action is answering the one question the chain-top
packet explicitly leaves open. The basis for the expected behaviour
is the serializer's own contract: its emitted byte stream differs
by exactly this one byte (the serializer packet's claim), so a
reconstruction of the signing payload must know which tag values
actually occur and where they are decided. The loss when it is
wrong is a payload whose tag byte differs from the node's — a
signature over different bytes. Independence by repro case: the
other open RE-005 packets cover the bincode varint size-state
(#2257), the bincode u64 reader state (#2300), the `rmp_signable`
`.rodata` census (#2311), the serializer (#2399), the caller tags
(#2419), the varint readers (#2412, #2422), the field1-5 caller
arguments (#2433) and the chain top (#2432); #2432 enumerates the
five top_caller callers and the twelve grand_b_caller slot sites
only as boundary counts — none traces them.

## Exact scope

| role | FDE half-open range | bytes | body SHA-256 |
| --- | --- | ---: | --- |
| ga_a1 | `0x35c57e0..0x35c588f` | 175 | `054054759fc73cb677ec85b38be72792497162953128d4d3613d7397fa10e120` |
| ga_a2 | `0x35c9c80..0x35ca1c1` | 1,345 | `afc39f31068d4101aa9b5c04eed9cdb37a0d69e2c0ed99f77da83cea2869d126` |
| ga_a3 | `0x3719a90..0x3719c4b` | 443 | `79372fc0afd5230a095c2f7a4f704ec06b00bdbcaf520b7383ebaf24b737bcf2` |
| ga_a4 | `0x3b87c20..0x3b880dc` | 1,212 | `335282c9ce9a817ce28dc383e0d25b9f19afccbedf41451ea820d406187d3444` |
| ga_a5 | `0x4301ce0..0x4301e82` | 418 | `65f01ebdb08d4a7f582d83e565017e234c8ab896678582bd6865203cff7cc360` |
| ga_a5_thunk | `0x3d9d160..0x3d9d16c` | 12 | `aaf47a1039989f5314d8a7bbf1958b00b8ad773fec115f33cf73657c7bc57c73` |
| ga_a5_feeder | `0x3713530..0x37136cb` | 411 | `d0c81e4baa052a3ad566b29dbdeca133a834059382dbdb8e00374d2da73f9465` |
| gb_b1 | `0x294af20..0x294b127` | 519 | `74b59319c55c3b1bca1cac4ad0f0756fd3ad1fe10db2e8cc92e8604a5cfad053` |
| gb_b2 | `0x2ae41e0..0x2ae6d66` | 11,142 | `90ae09003ca680bd4b5f32fec22ee1f7146cc1f67b758f8e2f2ac880545b730b` |
| gb_b3 | `0x2cde430..0x2ce0dd1` | 10,657 | `99c49a3e20f63cf199f2a160ba9560e439acb2b49a66968623aa9607acfa417b` |
| gb_b4 | `0x2e098e0..0x2e11140` | 30,816 | `3605ca6d67167d3359733cfee3b66ca0a8ca675731b909e97f331fb90d252dc6` |
| gb_b5 | `0x5a70c20..0x5a70cb5` | 149 | `843bb8c4d7a61b919b6a27b73bf4ad8122c9fe8d4a5b9a8a2d1dc53c4398da64` |
| gb_b6 | `0x5a70cc0..0x5a70d55` | 149 | `462351660670e7c30942a8588fe6cf72663834bb53628e8ee92e8f9a3833b8bc` |
| gb_b7 | `0x5a70d60..0x5a70e1c` | 188 | `38f5c89e8f56a685731ad83d8b9c7947f753f7f1d2abb2bc2f7f19265ca5d54e` |

The three owners above the export limit (gb_b2, gb_b3, gb_b4) are
retained as body hash + byte pins with window exports around every
pinned span; the remaining owners carry full disassembly exports.
The relied-upon links from the earlier packets (the serializer tag
rule, the top FDE tag load at `0x371336c`, the grand_b_caller tag
capture at `0x38d9c77`, and the grand_b_caller `.got` slot binding
`0x64e6c60`) are re-verified by this checker. Measured denominators:
the call and reference censuses below each cover the whole `.text`
(83,719,936 bytes), all 60,723 `.rela.dyn` entries, and — for the
raw census — the whole 105,896,032-byte file.

## Trace — grand_a path (the cell pointer's five callers)

The chain-top packet's cell pointer is the first qword of the
three-qword struct the top_caller FDE receives as its stack
argument 8: the top FDE loads the qword stored in that cell and
takes the byte at that address. A full-`.text` E8/E9 census finds
exactly five direct call sites into the top_caller FDE, one in each
ga_a caller, and each caller hands over a frame copy of a
three-qword struct whose field 0 is that cell pointer:

1. **ga_a1** (call `0x35c5834`). The struct is copied from the
   sub-struct at its record (second argument) +0x28, so the cell
   pointer is the record's +0x28 qword. The caller's own byte
   argument is zero-extended into the discriminator argument. After
   the call it runs a destructor on record +0x40. ga_a1 is itself
   called only from ga_a2 (`0x35ca00e`) and ga_a4 (`0x3b87f9f`),
   in both cases with a frame record as the argument.
2. **ga_a2** (call `0x35c9e56`). The struct is assembled from its
   record (second argument) fields +0x60/+0x68/+0x70; the cell
   pointer is the +0x60 qword. The discriminator argument is the
   constant 1. ga_a2 also materialises ga_a3's address by `lea`
   (`0x35c9d84`) for a registry it maintains, and calls ga_a1
   directly with the same frame struct as the record.
3. **ga_a3** (call `0x3719afa`). Same shape as ga_a1 (sub-struct at
   the record, here the first argument, +0x28; discriminator
   constant 1; the record's first qword is zeroed at entry). ga_a3
   has **no** direct call or jump site and no stored qword in the
   file: its address is materialised by `lea` in ga_a2
   (`0x35c9d84`) and ga_a4 (`0x3b87d1c`, stored into a registry slot
   at `0x3b87d23` beside a frame context record) — it is reached
   through that registry.
4. **ga_a4** (call `0x3b87de3`). Twin of ga_a2 (record fields
   +0x60/+0x68/+0x70; discriminator constant 0; same registry
   pattern).
5. **ga_a5** (call `0x4301da7`). Different shape: the struct is
   assembled on the frame — field 0 is the *address of the frame
   copy* of its third argument's +0x10 qword, field 1 a computed
   element pointer, field 2 its second argument. The cell pointer
   is therefore that frame slot, and the tag byte is the first byte
   of the object the third argument's +0x10 qword addresses.

In none of the five bodies does any instruction store to the
record fields the cell pointer is loaded from (an encoding-scoped
store census over the container fields, prefixes and ModRM sets
named in the checker, finds zero in each body), and none stores
through the cell pointer: on these four paths the pointer — and
the byte object — are forwarded from above, not written here.

**The ga_a5 path closes one level higher.** ga_a5 has no direct
call site either; a census finds exactly one jump site, in the
twelve-byte adapter **ga_a5_thunk** (`0x3d9d167`), which forwards
its own second argument as ga_a5's record and that record's +0x8
field as the second argument. The thunk has exactly one caller,
**ga_a5_feeder** (call `0x37135da`) — an FDE with the same container
shape as the top FDE (range `[arg3]..[arg3+0x8]`, cell pointer at
`[arg3+0x10]`). Per iteration the feeder performs the identical
two-dereference load from its own container (`0x3713590`,
`0x3713598`), stores the byte to a frame byte (`0x371359b`), builds
a record at `[rsp+0x70]` whose +0x10 field is *that frame byte's
address* (store at `0x37135c8`), and passes the record to the
thunk. So on this path the tag byte's value is fixed by the
feeder's own container cell chain — pinned end to end except for
the feeder's caller.

## Trace — grand_b path (the record's twelve call sites)

The chain-top packet counted twelve indirect calls through the
grand_b_caller `.got` slot `0x64e6c60` without following them. The
RIP-relative census (re-run here) maps them onto seven FDEs, and in
**every** one the record whose +0x11d byte is captured is built on
the caller's own frame immediately before the call; the tag byte
store is the last field written:

1. **gb_b5 / gb_b6 / gb_b7** (one site each) are small wrappers.
   Each stack-builds the record at `[rsp+0x8]` with a per-wrapper
   constant at +0x10 (**0xc4 / 0xc3 / 0xa8**) and stores the tag
   byte from **its own second-argument byte**, captured at entry
   (`0x5a70c33` / `0x5a70cd3` / `0x5a70d7d`), to record +0x11d (and,
   in gb_b5/gb_b6, also to record +0x48; in gb_b7 to +0x5c, with
   the fifth-argument byte at +0x5d). The wrappers have no direct
   call sites: each start address occurs exactly once in the file,
   as a stored qword (VAs `0x14c218` / `0x14c260` / `0x14c200`) —
   they are reached through a pointer table.
2. **gb_b1** (one site, in a loop) builds the record at
   `[rsp+0x60]` per iteration (+0x00 = 1, +0x10 = 0xc2, byte
   +0x18 = 2, +0x100 from its first argument's +0x10 field). The
   tag byte is the **first byte of the object pointed to by its
   first argument's +0x18 field**: that pointer is saved once at
   entry (`0x294af5a`; the store pattern is count-pinned unique in
   the body) and the byte is reloaded through it at every loop
   head (`0x294afb5`) before being stored to record +0x11d
   (`0x294b092`).
3. **gb_b2 / gb_b3** (three sites each) are twin method bodies on
   a long-lived context object (gb_b2: the object is the first
   argument; gb_b3: it is loaded as `[[arg1+0x8]]` at `0x2cde495`;
   both dispatch on the object's +0x21a byte). Each builds the
   record on its frame per site and stores the tag byte from a
   **fresh load of the object's +0x1e8 byte** immediately before
   each call. That field has exactly one store in each FDE
   (count-pinned): at `0x2ae44ce` / `0x2cde56b` it is written with
   the **low byte of the dword at object +0xa0**, in the entry arm
   that first stages a caller-supplied record into the object
   (gb_b3 by a 0x98-byte copy into object +0x10). Record +0x10 is
   0x97 at site 1 in both, blob-copied at gb_b2 site 2, and 0x87
   at gb_b2 site 3.
4. **gb_b4** (two sites) builds the record at `[rsp+0x50]` per
   site (+0x00 = 1; the +0x10 blob is copied from a frame record
   whose head qword is **0xdd** at site 1 and **0xdc** at site 2).
   The tag byte is the **byte at +0xbd5 of its second-argument
   object**, freshly loaded in each call block (`0x2e09b01`,
   `0x2e09f87`; count-pinned: exactly two such loads and two tag
   stores in the body).

## Result

Both tag source bytes are now grounded one level above the chain
top, at the writers the static bytes pin:

| reaching path | tag source byte, one level up | written by |
| --- | --- | --- |
| ga_a1 / ga_a3 | first byte of the object addressed by the qword in the cell at record +0x28 | not written in the traced callers — forwarded (boundary) |
| ga_a2 / ga_a4 | first byte of the object addressed by the qword in the cell at record +0x60 | not written in the traced callers — forwarded (boundary) |
| ga_a5 (via thunk + feeder) | the feeder FDE's own container byte, materialised onto its frame | the feeder's two-dereference load (`0x3713590`/`0x3713598`) and frame store (`0x371359b`) |
| gb_b1 | first byte of the object at the first argument's +0x18 pointer | reloaded per iteration (`0x294afb5`); the pointee's writer is above (boundary) |
| gb_b2 / gb_b3 | the context object's +0x1e8 byte | the FDE itself: low byte of the dword at object +0xa0 (`0x2ae44ce` / `0x2cde56b`, the only store) |
| gb_b4 | the second-argument object's +0xbd5 byte | not written in the traced FDE — read fresh per site (boundary) |
| gb_b5 / gb_b6 / gb_b7 | the wrapper's own second-argument byte | the wrapper's caller, through a pointer table (boundary) |

On every path the emitted byte remains `0x61` exactly when the
source byte equals 3 and `0x62` otherwise (the serializer's rule,
re-verified); no traced path materialises a constant *tag* — the
constants that do appear nearby are the record discriminants at
+0x10 (0xc4/0xc3/0xa8 in the wrappers, 0xc2 in gb_b1, 0x97/0x87 in
gb_b2/gb_b3, 0xdd/0xdc blob heads in gb_b4), which are separate
fields from the tag byte at +0x11d.

## Boundary

On the ga_a1/ga_a2/ga_a3/ga_a4 paths the cell pointer is still
only forwarded one level higher: the ga_a2 callers (FDE
`0x371d280`, site `0x371d31f`; FDE `0x371f380`, site `0x371f41b`)
copy it from their own first argument's record +0x60 field into
the frame record they pass, and the ga_a4 caller (FDE `0x3b913e0`,
site `0x3b91432`) passes a record returned by a helper call. The
ga_a5_feeder FDE has exactly one direct caller (FDE `0x3ec1b80`,
site `0x3ec1c0c`), not traced. On the grand_b path, the writers of
the gb_b2/gb_b3 +0xa0 source buffer (staged from a caller-supplied
record at entry), of the gb_b4 object's +0xbd5 byte, of the object
gb_b1's +0x18 field points to, and of the byte the table-dispatched
wrappers receive as their second argument are all above the traced
FDEs. In gb_b2/gb_b3 the +0x1e8 field may also retain a value set
before the traced entry arm ran, since its single in-FDE store is
arm-local. This packet does not name the record or object types
the pointers denote, does not say what the source bytes mean, and
does not observe any runtime value.

Next question: for each action family, which of these source
locations is actually exercised and what byte values occur there —
in particular whether the byte at the end of each chain is ever 3
(the `0x61` arm) outside the feeder path, and who writes the
gb_b2/gb_b3 +0xa0 staging buffer and the gb_b4 +0xbd5 byte.

## Reproduce

```sh
python3 -B tools/rmp_signable_tag_source_static.py --output research/work-items/RE-005-node115-rmp-signable-tag-source
python3 -B -m unittest discover -s tests -p 'test_rmp_signable_tag_source_static.py' -v
cd research/work-items/RE-005-node115-rmp-signable-tag-source && sha256sum -c MANIFEST.sha256
```

The checker authenticates the pinned binary (size and SHA-256)
before any analysis, re-derives every value above from the target
bytes, validates each pinned address and every chain call site as
a native instruction start against GNU objdump output, and carries
corruption controls (mutated container base, record field copy,
feeder tag store, wrapper tag store, object tag store, object tag
load, frame pointer store, indirect-call displacement and a wrong
public identity) that must all be rejected. It writes only the
packet directory, uses the Python standard library plus the
repository's own tools, and never executes the target.
