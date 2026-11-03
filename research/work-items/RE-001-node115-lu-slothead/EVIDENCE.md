# RE-001-node115-lu-slothead: the slot-head helper 0x63abd00

- Component ID: RE-001-node115-lu-slothead
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), `artifacts/node/115/hl-node`
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all byte claims; inference for the
  tree-shape interpretation (parent / next-sibling / first-child roles
  of `+0x28` / `+0x30` / `+0x38`, and the two-round pairing model);
  unresolved for `[slot+8]` semantics, the two-round stopping rule,
  the five non-release callers' purposes, and the cache invariant
- Scope included and excluded: included — the FDE
  `0x63abd00..0x63ac0cc` only (972 bytes), its census, and its return
  contract. Excluded — caller FDEs (cited by address only), the
  release helper's cache write itself (#224), and any node bytes
  claimed by packets #183–#224.

## Reproduce

Working directory: a worktree of upstream main `8fd8db6` with the
node #115 artifact present. Tools: `objdump` and `readelf`
(binutils), Python 3. No execution of the node binary at any point;
all evidence is byte reads and disassembly of the file.

- FDE bounds: `readelf --debug-dump=frames artifacts/node/115/hl-node`
  gives `FDE cie=00000000 pc=00000000063abd00..00000000063ac0cc`.
- Full disassembly: `objdump -d --start-address=0x63abd00
  --stop-address=0x63ac0cc artifacts/node/115/hl-node` (972 bytes,
  2 `ret` sites, 0 `call` instructions; every jump target inside
  the FDE).
- Census: whole-file byte scan for `E8` with a rel32 target of
  `0x63abd00` (6 sites, each confirmed by per-site objdump as
  `call 63abd00`); same scan for `E9` (0 sites); rip-relative `LEA`
  scan (0 sites); `.rela.dyn` addend scan over 60,723 entries
  (0 hits).
- Coordinate system: `.text` file offset = VA − 0x1000;
  `.data.rel.ro`/`.got` = VA − 0x2000; `.rodata` = VA as-is.
  `.rela.dyn` addends are used for GOT census because RELATIVE
  `.got` slots are zero-filled in the file.

## Evidence

Entry (`sh_entry.hex`, `0x63abd00..0x63abd36`): `endbr64`,
`head = [slot]`, `NULL` check jumping to the `NULL`-return path,
callee-saved pushes, `movq $0, 0x8(%rdi)` zeroing `[slot+8]`, and
the single-node check on `head+0x30`.

Comparison idiom (`sh_cmp.hex`, `0x63abd8f..0x63abdb6`): the
`setb`/`sbb` signum idiom on `+0x20` with a `+0x8` tiebreak — the
same idiom #217's slot-claim and #219's slot-insert use. Result
`-1` means the second node's key is smaller; any other result means
greater-or-equal.

Winner attach (`sh_splice.hex`, `0x63abe00..0x63abe36`): the
greater-or-equal pair branch — a 16-byte `movups` pair store into
the loser's `+0x28` slot, the backlink write, the
`winner+0x38 = loser` store, and the `+0x30` chain advance. This is
the store sequence that establishes `+0x28` = parent,
`+0x30` = next sibling, `+0x38` = first child.

Main loop head (`sh_loop.hex`, `0x63abe36..0x63abe60`): the pair
walk — load `next = current+0x30`, exit when `next` is `NULL`,
load the node after next, zero the node-after-next's `+0x28`
pair when it exists, and load the current node's `+0x20` key word.

Tail (`sh_tail.hex`, `0x63abf23..0x63abf4d`): the
winner-key-`>=`-head-key path — the pair store into `head+0x28`,
the backlink, `winner+0x38 = head`, `head` moved into the return
register, and `[slot] = winner`.

Return contract, established by following every exit path:
empty slot → `NULL`; single-node chain → `head`; otherwise the
tail's selected node, which always equals `[slot]` on return.
The two `ret` sites are `0x63abf5a` (shared tail exit) and
`0x63ac0c3` (empty-slot exit). No path frees a node, returns a
status, or leaves a node unlinked: losers are reattached as
first-children and winners are chained, so the node set is
preserved.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed in
this packet. The packet is a bounded static-analysis record; the
two-round pairing model is an inference from the disassembly,
stated as such, with the raw exhibits beside it for independent
checking.

## Results and limitations

Machine-readable metrics with explicit denominators: 5 excerpts,
231 bytes, 64 strict mnemonic lines; census 6 E8 / 0 E9 / 0 LEA /
0 GOT over 60,723 `.rela.dyn` entries; FDE 972 bytes; MANIFEST
15/15 entries. What passed: verifier exit 0, unit tests 10/10,
`make verify` exit 0, `make catalogue-check` exit 0, `make test`
77 files with only the pre-existing catalogue Errno 18 failure.
What remains unknown: `[slot+8]` semantics, the two-round stopping
rule, the five non-release callers' purposes, whether later
traversals follow `+0x38` children, and the cache invariant.
Next question: decode FDE `0x63b0980..0x63b15e9` — why it calls
`0x63abd00` four times, and how its slot relates to the
allocator's pool slots.
