# RE-001-node115-lu-free-dealloc: the free target, its sibling field drops, and their shared deallocator

- Component ID: RE-001 (node #115 lu family)
- Target release and full SHA-256: node #115 hl-node, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `8fd8db6`
  (`8fd8db680ec4bfef40996e5616bce3d5156d0b86`), confirmed unmoved by
  fetch before analysis
- Claim status: observation (all claimed bytes read from the binary;
  the "list-full guard" reading of the `+0x372` compare and the
  "runtime-initialized allocator" reading of the `.bss` tables are
  marked as inference in the evidence below)
- Scope included and excluded: included — the free target `0x5a8e3c0`,
  the sibling field drops `0x5a8c9f0` / `0x5a8c110`, the shared
  deallocator fast path `0x635de30`, and the whole-binary census for
  all four addresses. Excluded — the drain helper `0x51e8720`, the
  field-drop callees `0x5a50a10` / `0x5a4d200`, the deallocator slow
  path `0x635c6d0` (cited, not decoded), and #200's delegates
  `0x51f3e20` / `0x57ec1b0` and unwind callee `0x1680cab`.

## Reproduce

Static analysis only; the node binary is never executed.

```
cd <worktree>
objdump -d --start-address=0x5a8e3c0 --stop-address=0x5a8e493 artifacts/node/115/hl-node
objdump -d --start-address=0x5a8c9f0 --stop-address=0x5a8ca2c artifacts/node/115/hl-node
objdump -d --start-address=0x5a8c110 --stop-address=0x5a8c14c artifacts/node/115/hl-node
objdump -d --start-address=0x635de30 --stop-address=0x635dec6 artifacts/node/115/hl-node
python3 tools/node115_lu_free_dealloc.py
python3 -m unittest tests.test_node115_lu_free_dealloc -v
```

Tool versions: system `objdump` / `readelf` (binutils), Python 3.
Input digest: see SHA-256 above. No execution side effects.

## Evidence

Coordinate system (node #115 hl-node): `.text` file offset =
VA − 0x1000 (section VA `0x1419300`, offset `0x1418300`);
`.data.rel.ro` / `.got` file offset = VA − 0x2000;
`.rodata` VA as-is. Verified against section headers.

Claimed bodies (body proper through `ret`; landing pads cited, not
claimed):

- free `0x5a8e3c0..0x5a8e493`: 211 bytes, 59 strict mnemonic lines
  (`free.hex`, `free.objdump.txt`). Buffer disposal: signed length
  at `[rbx+0x18]`; nonzero length with non-overflowing negation frees
  `[rbx+0x20]` directly with size `24 × length` via GOT `0x64df4a0`
  (call at `0x5a8e426`); negation-overflow case drains through
  `0x51e8720` until `[rsp+0x48] == 0`; null buffer builds empty
  iterators. Shared tail: `cmp $-1,%rbx` at `0x5a8e463`,
  `lock decq 0x8(%rbx)` at `0x5a8e469`, size `0x38` at `0x5a8e470`,
  tail jump through GOT `0x64df4a0` at `0x5a8e483`. Landing pad
  `0x5a8e493..0x5a8e4bb` (dec + `call` + `_Unwind_Resume` at
  `0x63f0a50`).
- field drop `0x5a8c9f0..0x5a8ca2c`: 60 bytes, 21 strict lines.
  Field `[rbx+0x10]` dropped via direct call `0x5a50a10` at
  `0x5a8c9fb`; `-1` guard at `0x5a8ca00`; `lock decq 0x8(%rbx)` at
  `0x5a8ca06`; size `0xb80` at `0x5a8ca0d`; tail jump through GOT
  `0x64df4a0` at `0x5a8ca1e`. Landing pad `0x5a8ca2c..0x5a8ca54`.
- field drop `0x5a8c110..0x5a8c14c`: 60 bytes, 21 strict lines.
  Field `[rbx+0x18]` dropped via direct call `0x5a4d200` at
  `0x5a8c11b`; `-1` guard at `0x5a8c120`; `lock decq 0x8(%rbx)` at
  `0x5a8c126`; size `0xc8` at `0x5a8c12d`; tail jump through GOT
  `0x64df4a0` at `0x5a8c13e`. Landing pad `0x5a8c14c..0x5a8c174`.
- deallocator fast path `0x635de30..0x635dec6`: 150 bytes,
  29 strict lines (`dealloc.hex`, `dealloc.objdump.txt`). Guards:
  `cmp $0x1000,%rsi` at `0x635de34` (size bound), `test %edx,%edx`
  at `0x635de41` (third argument must be zero), `test $0xfff,%edi`
  at `0x635de49` (page-aligned pointers diverted); every guard
  failure jumps to `0x635ded0`, which tail-jumps to the general
  free at `0x635c6d0` (`e9 fb e7 ff ff` at `0x635ded0`). Fast path:
  class index `table 0x67277c0[(size+7)/8]`, class size
  `table 0x6727a00[class]`; per-thread budget check
  (`fs:0x348` used + class size vs `fs:0x350` limit, TLS base
  `0xffffffffffffef58` = `-0x10a8`); per-class head at `+0x360`
  in a 24-byte slot compared (low 16 bits) against the bound at
  `+0x372` — read as the list-full guard (inference); on success
  head decreases by 8 (`lea -0x8(%r9)` at `0x635deae`), the freed
  pointer is stored at the new head (`mov %rdi,-0x8(%r9)` at
  `0x635deb9`), the budget is updated, `ret` at `0x635dec5`.
  No store touches the freed block itself; no syscall appears on
  this path. Both size-class tables lie in `.bss`
  (`0x64ffe40..0x6728e24`, NOBITS) — runtime-initialized
  (inference from section type, not from observed init code).

Relocations (RELATIVE, type 8, from `.rela.dyn`):
`0x64df4a0` → `0x635de30` (deallocator),
`0x64e7278` → `0x5a8e3c0` (free),
`0x64e7270` → `0x5a8c9f0`,
`0x64e7208` → `0x5a8c110`.
Note: RELATIVE `.got` slots are zero-filled in the file, so the
GOT census below goes through `.rela.dyn` addends, not a
file-content scan.

Census (whole-`.text` raw scan; FF 15 sites spot-verified genuine
by disassembly): free — 0 E8, 0 E9, 0 LEA, 0 absolute refs outside
`.rela.dyn`, 46 FF 15 sites via `0x64e7278`; field drop `0x5a8c9f0`
— 0 / 0 / 0 / 0, 27 FF 15 sites via `0x64e7270`; field drop
`0x5a8c110` — 0 / 0 / 0 / 0, 141 FF 15 sites via `0x64e7208`;
deallocator slot `0x64df4a0` — 98,976 FF 15 sites binary-wide
(raw scan; sites `0x141960a`, `0x14198ea`, `0x14218e3`,
`0x143a5a0` verified genuine). Caller-side pattern observed at
verified drop sites: `lock dec` on a field, then the GOT call at
zero — the same template #201 reported for release sites.

Analysis completeness: complete for the four claimed bodies and the
census; the slow path, drain helper, and field-drop callees were
deliberately not decoded (see scope).

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction is claimed by
this packet; it is a static evidence packet only.

## Results and limitations

What passed: verifier exit 0, unit tests 8/8, MANIFEST 13/13,
`make verify` / `make catalogue-check` exit 0, `make test` 77 files
with only the pre-existing catalogue Errno 18 failure.
What remains unknown: the slow path's disposition of refused
blocks; the drain helper's element semantics; the field-drop
callees' own layouts. No gate is requested by this packet.

Finish with a concrete next question: decode the deallocator's
slow path `0x635c6d0` — where do blocks refused by the fast path
(oversized, aligned, page-aligned, or list-full) actually go?
