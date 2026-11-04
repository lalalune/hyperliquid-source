# RE-014: node #115 field-adapter table shim at table+40

- Component: RE-014 migration validation; foundation (field/newline
  adapter family).
- Target: node #115, 105,896,032 bytes; SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: the merged field-adapter drift packet binds the 48-byte
  adapter table at `0x64078f8` and retains its three pointer
  relocations, but leaves the +32 and +40 callees opaque; the merged
  newline packet qualifies the +24 bulk callee `0x1686bd0` and the
  field-adapter byte-arm packet qualifies the +32 callee `0x1686b70`.
  What does the +40 callee `0x168aa10` do to its arguments before it
  hands control to its tail target?
- Observation: `0x168aa10` is a four-instruction argument shim. It
  moves argument 3 into the argument 4 register and argument 2 into
  the argument 3 register, inserts the adapter table itself
  (`0x64078f8`) as the new argument 2, forwards arguments 1, 5 and 6
  unchanged, and tail-jumps through GOT slot `0x64df6f0`, RELATIVE-
  bound to `0x1680500`. The caller's argument 4 value is overwritten
  by the shift and reaches no register. It is reached only through
  the table: zero direct callers or jumps and exactly one relocation
  reference exist in the capture.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| adapter table +40 callee (argument shim) | `0x168aa10..0x168aa23` | 19 | 4 |

The measured denominator is **one complete FDE, 19 bytes**, retained as a
complete native export. The adapter table, its header words and the tail
slot binding are separate context domains, pinned but not counted as
recovered function bytes. The body is hash-pinned without
normalization. This is not a raw-equal or normalized cross-function or
cross-release equivalence claim.

## Trace stages

1. **Table binding (re-derived).** The table at `0x64078f8` stores three
   header qwords raw — `0x0`, `0x18`, `0x8` — and three pointer slots
   whose inline qwords are zero; the bindings come from symbol-free
   RELATIVE (type 8) relocations: +24 → `0x1686bd0`, +32 → `0x1686b70`,
   +40 → `0x168aa10`. The drift packet retained the same three
   relocations as context and the newline packet recorded the +32/+40
   targets as opaque; the byte-arm packet qualified +32. This packet
   qualifies +40.
2. **Census.** A full-`.text` E8/E9 scan finds **zero direct callers
   and zero direct jumps** to `0x168aa10`. In `.rela.dyn` exactly one
   addend names it: the table+40 slot `0x6407920`. Its raw 8-byte
   address form occurs exactly once in the whole file — as that
   relocation's addend field. No other table, GOT slot or code site
   references it.
3. **Argument shift.** `mov rcx,rdx` at `0x168aa10` copies argument 3
   into the argument 4 register; `mov rdx,rsi` at `0x168aa13` then
   copies argument 2 into the argument 3 register. The order matters:
   the first move vacates `rdx` before the second overwrites it, so
   no value is lost except the entry `rcx` (argument 4), which is
   overwritten before it is read anywhere.
4. **Table insertion.** `lea rsi,[rip+0x4d7cedb]` at `0x168aa16`
   materializes `0x64078f8` — the adapter table itself, the same
   table whose +40 slot names this shim — into the argument 2
   register. The inserted value is pinned by the instruction's own
   displacement, not by the table relocation.
5. **Tail jump.** `jmp QWORD PTR [rip+0x4e54ccd]` at `0x168aa1d`
   transfers control indirectly through slot `0x64df6f0`; the slot's
   binding is a symbol-free RELATIVE relocation to `0x1680500`
   (re-derived from `.rela.dyn`, not assumed). The shim pushes
   nothing and adjusts no stack pointer: `rsp` and every stack slot
   are exactly as at entry, so the return address the tail target
   eventually returns to is the shim caller's, and stack-passed
   arguments keep their entry offsets. `mov`, `lea` and the indirect
   jump modify no flags, so the tail target also inherits the entry
   flag state. `rdi`, `r8` and `r9` are never written.

## Result summary

For any values in the six argument registers at shim entry, the
registers at the tail jump to `0x1680500` are:

| Register | At tail jump | Source |
| --- | --- | --- |
| `rdi` (argument 1) | entry argument 1 | forwarded |
| `rsi` (argument 2) | `0x64078f8` | inserted adapter table |
| `rdx` (argument 3) | entry argument 2 | shifted |
| `rcx` (argument 4) | entry argument 3 | shifted |
| `r8` (argument 5) | entry argument 5 | forwarded |
| `r9` (argument 6) | entry argument 6 | forwarded |

The entry argument 4 value (`rcx`) is the only input that does not
reach the tail target in any register. The transformation is total:
it depends on no input value, memory contents or flag state. Both
retained rows (symbolic and distinct-marker values) are in
`records.json`.

## Explicit boundary and next question

Only the shim's own 19 bytes are qualified. The transformation is
stated for the six integer/pointer argument registers; nothing here
establishes what `0x1680500` computes with the six values it
receives, which callers invoke the shim through the table or with
which argument values, what the entry argument 4 means to those
callers, or any nominal type for the table or the arguments. The
sibling callees at table+24 and table+32 are qualified by the merged
RE-014 newline packet and the RE-014 field-adapter byte-arm packet
(open PR #2401 at census time) and are cited context, not
re-derived. No gate is claimed.

Next question: what `0x1680500` computes with the adapter table it is
handed as its second argument, and which entry argument 2 and 3
values its callers route through this shim.

## Reproduce and validation

From repository root with the materialized pinned capture and native
GNU tools on PATH:

```sh
python3 -B tools/field_adapter_table_shim_static.py --output research/work-items/RE-014-node115-field-adapter-table-shim
python3 -B -m unittest discover -s tests -p test_field_adapter_table_shim_static.py -v
(cd research/work-items/RE-014-node115-field-adapter-table-shim && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or native
calls. Readelf/objdump receive a private byte-identical snapshot; the
snapshot path is replaced with `<authenticated-node115>` in retained
text. Wrong-release, truncated and same-size modified public inputs are
rejected before output creation.

Focused controls alter the actual shift bytes, the table insertion
opcode and displacement, the tail jump opcode and slot displacement,
the table header words, each table relocation addend, the tail slot
addend and the FDE record; each makes the checker reject the
counterfactual. Below the full public digest gate, this checks the
named obligations, not arbitrary-byte error detection or target
execution equivalence.

No captured executable/emulator, live chain/wallet/signing action or
network access is performed. Captured inputs/imported code/pins and
all progress gates are preserved. No hosted-CI result or
whole-component completion is claimed.
