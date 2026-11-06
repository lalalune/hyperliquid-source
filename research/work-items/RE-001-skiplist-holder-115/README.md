# RE-001: node #115 memtable-factory record holders — SkipListFactory 0x6064440 with its five construction sites, shared_ptr installation and ":" setters

Task: RE-001. Bounded question: how is the memtable factory that the
options object carries built, installed and replaced — what exactly
does the SkipListFactory record holder 0x6064440 register, how does
the options object own it at +0x128/+0x130, when does the validation
routine rebuild it, and how do the two ":" setters build a fresh
factory from a "name:value" string?

Target: node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`work/hl-node-115.bin`, verified against
`provenance/artifacts.json`). All addresses below are node #115
virtual addresses; all excerpts are whole-function verbatim
objdump output. The mnemonics in the excerpts (`endbr64`
included) are genuine instructions present in the target binary,
not placeholders.

## What this pins (complete behaviour, not a fragment)

1. **The holder is a `rocksdb::SkipListFactory`.** The ctor
   `0x6064440` (340 bytes, `0x6064440..0x6064551`) builds a 0x28-byte
   object: vtable `0x64d27b0` at +0x00, whose typeinfo name is
   `N7rocksdb15SkipListFactoryE`; a record vector at +0x08
   (`{begin +0x08, end +0x10, cap +0x18}`, zeroed); and the ctor's
   second argument stored at +0x20. It registers exactly one
   0x30-byte record `{key, a, b}` through the push-back
   `0x6099ce0`: key `"SkipListFactoryOptions"` (22 chars, built
   from the 16-byte chunk `"SkipListFactoryO"` at `0x452f70`
   stored at key+0x00, plus the 8-byte immediate `"yOptions"`
   stored at key+0x0e), `a` = the ctor's second
   argument (the value at holder+0x20), `b` = `0x6505c40`.
   `0x6505c40` is an address in the zero-filled tail of the data
   segment (no file bytes, no RELATIVE record): the record stores
   the address itself; whatever it points to at runtime is not
   recoverable from the static binary and is recorded as the
   address, not dereferenced.
2. **First install: the base init.** The options base init
   `0x60b3c30` (re-shipped from #3254) allocates the 0x28-byte
   holder, calls the ctor with `rsi = 0` (so the record's `a` is
   0), and installs it as an inline shared_ptr at options+0x128
   (object) / +0x130 (control): the control is a separate 0x18-byte
   `_Sp_counted_ptr<rocksdb::SkipListFactory*>` block (vtable
   `0x64d3780`, typeinfo
   `St15_Sp_counted_ptrIPN7rocksdb15SkipListFactoryELN9__gnu_cxx12_Lock_policyE2EE`),
   holding the counts qword `0x100000001` (`{use=1, weak=1}`) at +0x08
   and the holder pointer at +0x10. The same function also builds
   a 0x1c-byte heap block of seven u32 fields, each 1 (four from a
   16-byte copy of `.rodata` `0x452930`, two more from the qword at
   the same address, one from an immediate store), and stores its
   address at options+0xb0 with end/cap pointers at +0xb8/+0xc0
   (both heap+0x1c) and +0xc8 = 0 — a vector-like triple; its role
   is UNKNOWN, recorded as seven ones, not interpreted further.
   (The string `"column family ID"` that follows the four 1-dwords
   in `.rodata` at `0x452930` is not copied into the block.)
3. **Replacement: the name gate.** The options validation routine
   `0x5d946b0` (`0x5d946b0..0x5d9518d`, 2781 bytes; only the
   factory-rebuild branch is pinned here, the other validation
   branches are out of scope) reaches the rebuild only when
   options+0x290 is 0. It then reads the current holder's name
   through its vtable slot 14 (`0x6062f70`, which returns
   `"SkipListFactory"` for a SkipListFactory), takes its
   `strlen`, and compares `min(len, 22)` bytes against two
   literals, requiring `len == 22` in both cases:
   `"HashSkipListRepFactory"` (`0x432031`, 22 chars) and
   `"HashLinkListRepFactory"` (`0x43a3e1`, 22 chars). Either hash
   factory name passes — the hash factory's own Name() (vtable
   slot 14, `0x605ea40`) returns `"HashLinkListRepFactory"`, so a
   HashLinkListRepFactory is replaced just like a
   HashSkipListRepFactory. On a pass it allocates a 0x38-byte
   `_Sp_counted_ptr_inplace<rocksdb::SkipListFactory>` control
   block (vtable `0x64c9c00`, typeinfo
   `St23_Sp_counted_ptr_inplaceIN7rocksdb15SkipListFactoryESaIvELN9__gnu_cxx12_Lock_policyE2EE`),
   with the counts qword `0x100000001` at +0x08 and the holder
   built in place at +0x10 by the ctor (again with `rsi = 0`),
   installs the pair at +0x128/+0x130, and releases the old
   control through the shared release helper `0x5d350c0` when it
   is non-null. Net semantics: a hash skiplist factory is
   normalised to a plain SkipListFactory during options
   validation.
4. **The ":" setters.** Two twin functions parse a
   `"name:value"` string and install a fresh factory at the slot
   `*rbp` (`rbp = *rdx`, the caller's holder slot), destroying the
   old factory through its vtable slot 1 (`0x6063430` for a
   SkipListFactory) when non-null:
   - `0x61935b0` (`0x61935b0..0x6193791`, 481 bytes, the
     skip_list arm): finds `":"` (`0x441b18`) with
     `basic_string::find`; with no `":"` it builds the default
     holder (`rsi = 0`, record `a = 0`); otherwise it takes the
     substring after `":"` (out-of-range throws
     `std::out_of_range("basic_string::substr")` via
     `0x63f1040`), parses it as a decimal through the stub
     `0x61d1ef0` into the K/M/G/T parser `0x61d1540` (pinned in
     #3237/#3251), and builds the holder with `rsi` = the parsed
     value.
   - `0x6193390` (`0x6193390..0x6193559`, 457 bytes, the
     hash_linkedlist arm): the same `":"` parse, but it builds a
     `rocksdb::(anonymous namespace)::HashLinkListRepFactory`
     through the ctor `0x605f150` with
     `(value-or-50000, 0, 0x1000, 1, 0x100)`; with no `":"` the
     value is the default `50000` (`0xc350`).
   The HashLinkListRepFactory ctor `0x605f150`
   (`0x605f150..0x605f2fe`, 318 bytes) builds a 0x40-byte object
   (vtable `0x64d2230`, typeinfo name as stored
   `*N7rocksdb12_GLOBAL__N_122HashLinkListRepFactoryE` — the
   stored name carries a leading `*` byte; it demangles to
   `rocksdb::(anonymous namespace)::HashLinkListRepFactory`)
   with fields +0x20 = value, +0x28 = `0x100`, +0x30 = 0,
   +0x38 = `0x1000`, +0x3c = 1, and registers one record
   `{"HashLinkListRepFactoryOptions", value, 0x6505b80}` (29-char
   key from `"HashLinkListRepF"` at `0x451100` stored at key+0x00
   plus `"epFactoryOptions"` at `0x4532c0` stored at key+0x0d;
   `0x6505b80` is a BSS
   address like `0x6505c40`).
5. **Registry: how the setters are reached.** The setters have no
   direct callers and no RELATIVE installations; they are reached
   through `lea` references from the factory registry builder
   `0x6195290` (`0x6195290..0x619686d`, 5597 bytes; only the two
   entries below are pinned — the builder's other factory entries
   and the insert helper `0x5d655b0` are out of scope). It builds
   two entries:
   - `"skip_list"` (short) / `"SkipListFactory"` (long) → setter
     `0x61935b0`, accessor `0x6192860` (index-0 value `0x64d65d8`);
   - `"hash_linkedlist"` / `"HashLinkListRepFactory"` → setter
     `0x6193390`, accessor `0x6192890` (index-0 value `0x64d65e8`).
   Each accessor (`0x6192860`/`0x6192890`, 45 bytes) takes
   `(out, value, index)`: index 0 stores its constant address,
   index 1 stores `value`, anything else stores nothing; it
   always returns 0.

## The five construction sites (census)

The holder ctor `0x6064440` has exactly five direct call sites:
`0x60b3dd2` (base init, heap holder + separate control),
`0x5d94ce8` (replacement, inplace control), `0x6193685` and
`0x619371a` (the skip_list setter's parsed and default paths),
and `0x5f10517` (a stack-temporary holder fed to `0x6063640`,
SkipListFactory vtable slot 19, whose 0x58-byte product is stored
at caller+0xa58). The fifth site is NOT part of this PR's
behaviour: it builds a transient holder for a different consumer
(`0x6063640`, out of scope) rather than installing a factory.
It is recorded in the census and named here so a later work item
can pick it up.

## Vtable slots pinned from relocations.txt

SkipListFactory vtable `0x64d27b0` (23 slots): 0 `0x60633a0`,
1 `0x6063430` (used by both setters to destroy the old holder),
2 `0x609d760`, 3 `0x609dc40`, 4 `0x5d32560`, 5 `0x6095e70`,
6 `0x6096790`, 7 `0x5d2e090`, 8 `0x60956f0`, 9 `0x609d0e0`,
10 `0x60986b0`, 11 `0x6095710`, 12 `0x609de80`, 13 `0x609d980`,
14 `0x6062f70` (Name → `"SkipListFactory"`; used by the gate),
15 `0x6063970`, 16 `0x5d2e770`, 17 `0x5d2ca00`,
18 `0x6062f80` (→ `"skip_list"`), 19 `0x6063640` (the transient
consumer), 20 `0x5f04d90`, 21 `0x6062f90`, 22 `0x6062fa0`.
Slots other than 1, 14, 18 and 19 are recorded by
address only; their methods are not named here.

HashLinkListRepFactory vtable `0x64d2230` (23 slots):
0 `0x605eee0`, 1 `0x605ef70`, 2 `0x609d760`, 3 `0x609dc40`,
4 `0x5d32560`, 5 `0x6095e70`, 6 `0x6096790`, 7 `0x5d2e090`,
8 `0x60956f0`, 9 `0x609d0e0`, 10 `0x60986b0`, 11 `0x6095710`,
12 `0x609de80`, 13 `0x609d980`, 14 `0x605ea40` (Name →
`"HashLinkListRepFactory"`), 15 `0x5d32a30`, 16 `0x5d2e770`,
17 `0x5d2ca00`, 18 `0x605ea50`, 19 `0x605eb40`, 20 `0x5f04d90`,
21 `0x605e920`, 22 `0x605e930`. Slots 2..13, 16, 17 and 20 are
shared with the SkipListFactory vtable; slots 0, 1, 14, 15, 18,
19, 21 and 22 differ. Un-named slots are recorded by address
only (see relocations.txt for the full range).

Control vtables: separate control `0x64d3780` (5 slots:
`0x60b1dc0`, `0x60b1e40`, `0x60b1e10`, `0x60b1e50`, `0x60b1e30`);
inplace control `0x64c9c00` (6 slots: `0x5d89720`, `0x5d897c0`,
`0x5d89750`, `0x5d89ac0`, `0x5d89e30`, and slot 5 = 0, no
RELATIVE record).

## What is NOT claimed

- The 0x1c-byte seven-ones heap block whose address sits at
  options+0xb0: recorded as seven u32 1s; its role is unknown.
  (The `"column family ID"` string in `.rodata` at `0x452930`
  is not part of the block.)
- The record `b` fields (`0x6505c40`, `0x6505b80`): BSS addresses
  with no file bytes; their runtime pointees are unknown.
- The rest of the validation routine `0x5d946b0` beyond the
  factory-rebuild branch, the rest of the registry builder
  `0x6195290` beyond the two entries, the insert helper
  `0x5d655b0`, the transient consumer `0x6063640` and its 0x58-byte
  product, and the un-named vtable slots: out of scope, listed
  here as follow-up ground, not as findings.
- The decimal parser `0x61d1540` is not re-shipped: its behaviour
  is pinned in #3237/#3251 and this packet pins only the stub
  `0x61d1ef0` that jumps to it.

## Verification

`python3 research/work-items/RE-001-skiplist-holder-115/verify.py`
prints ALL CHECKS PASSED: digest, provenance, manifest, excerpt
regeneration byte-for-byte from fresh objdump runs, every excerpt
instruction byte-for-byte against the raw binary, spot
instructions, FDE ranges, the relocation set, the literals, census
consistency (including the two lea references), semantic records
re-derived from the excerpts (vtable slot tables, typeinfo names
via c++filt, both record keys rebuilt from their constant chunks,
the gate literals, the seven-ones object), and the model tests.
`python3 tests/test_skiplist_holder_115.py` runs the model checks
(pytest is not installed on this VM, so the test file runs
directly).
