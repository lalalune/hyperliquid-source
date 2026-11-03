# RE-006 node 115 join helper and element layout

## Scope

Packet `RE-006-node115-join-helper-element` answers the two
questions left open by `RE-006-node115-join-callee` (#2558):

1. What body sits behind GOT slot `0x64dfaf8`, the one helper the
   join callee `0x36a0d80` calls seven times under an assumed
   unsigned 128-bit division contract?
2. Who writes the eight element fields the callee reads
   (`+0x40`, `+0x58`, `+0x78`, `+0x60` on every path; `+0x90`,
   `+0x98` in its clamp phase; `+0x80` or `+0x88` per arm) — in the
   node presentation the elements are `node + position × 0xb0`,
   in the flat presentation `base + index × 0xb8 + 8`?

Everything is established against the Linux x86-64 node 115
artifact (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105,896,032 bytes). File offsets are resolved through the section
table throughout (VA − 0x1000 in `.text` / `.got` / `.rela.dyn`;
`.rodata` is identity-mapped).

## Short answer — the helper

- **The slot resolves statically.** Slot `0x64dfaf8` lies in
  `.got`, its file-initialised content is zero, and it carries
  exactly one relocation: an `R_X86_64_RELATIVE` (type 8, symbol
  index 0) whose addend is `0x63efec0`. The helper is the body at
  **`0x63efec0..0x63eff7e`, 190 bytes**, SHA-256
  `989c6ef7689fca20c83d7a615696bb50b66e6d650095192c333970f100a4668e`,
  an exact FDE start, pinned here by digest and by every one of
  its 67 instruction rows, with a full-body export.
- **The assumed contract is exact.** The body is a register-only
  unsigned 128-by-128 division routine in the
  `__divti3`/`__udivti3` shape: numerator in `rdi` (low) and `rsi`
  (high), denominator in `rdx` (low) and `rcx` (high), quotient
  returned in `rax` (low) and `rdx` (high). Entry saves the
  denominator-low in `r8` (`0x63efec0`) and dispatches on the
  denominator-high (`test %rcx,%rcx; je 0x63eff39`). It makes
  **no call**, touches **no memory** (zero memory operands in 67
  rows), has four `ret` sites and six `div` sites, and no branch
  leaves the body. The callee's seven call sites, re-verified here
  against its pinned digest, match this contract at every site.
- **Edge behaviour: a zero denominator traps; nothing else can.**
  There is no zero guard anywhere in the body. With `rcx = 0` and
  `rdx = 0`, the low path compares numerator-high against `r8 = 0`
  (`cmp %r8,%rsi; jae` at `0x63eff39`), which is always taken, and
  both sub-paths end in a hardware `div` whose divisor is `r8` /
  `r8d` = 0 — a #DE fault, not a returned value, saturation, or a
  loop. Quotient overflow is unreachable by construction: the
  single-`div` path is entered only when numerator-high <
  denominator-low (quotient < 2^64); the two-step paths first
  reduce the high half modulo the denominator; the normalised path
  (`rcx ≠ 0`) divides a pre-shifted dividend (`rdx = num_hi >> 1`)
  by the normalised denominator-high, which the `bsr`/shift/`cmove`
  construction pins into `[2^63, 2^64)` and therefore never zero.
- **The helper is a shared primitive, reached only via the slot.**
  The modrm-position census of #2558's method finds **305
  rip-relative references** to slot `0x64dfaf8` binary-wide, all
  with trailing-immediate length 0 — 262 in `call *disp(%rip)`
  form (preceding opcode `0xff`) and 43 in `mov disp(%rip)` form
  (opcode `0x8b`, loading the pointer) — and **zero direct `E8`
  calls** to the body `0x63efec0`. The callee's seven sites are a
  small, decode-verified subset (pinned in #2558).

## Short answer — the element fields

**No writer for any of the eight fields exists in the traced
window; all eight are incoming there.** The window is stated
exactly: the sibling search `0x35bf460`, the family fallback
`0x4556410`, the join callee `0x36a0d80`, its four callers pinned
in #2558, and all 63 sibling-search caller FDEs pinned in #2542
(digests re-verified here for all 63 + 4).

- The sibling search stores only its four out-record fields
  (`+0x0/+0x8/+0x10/+0x18` through the record pointer, at
  `0x35bf4e7/0x35bf4db/0x35bf4df/0x35bf4e3`) — no element field.
- The fallback (body `0x4556410..0x4556544`, 308 bytes, SHA-256
  `3d150ceb58b41495a86136ef7c0f8b007889d82daeae6284c6916d39c8408fce`,
  pinned by all 89 rows) makes **zero stores**: it is a pure
  lower_bound over the flat array (six `imul $0xb8` sites,
  key compared at record `+0x0`). The callee itself makes zero
  element stores (#2558, re-verified here).
- The three join FDEs contain **no store at all** at any of the
  eight displacements through a non-stack base. The fourth caller
  `0x2f0f3b0` contains exactly two — `movsd %xmm7,0x40(%r15)` and
  `movsd %xmm3,0x58(%r15)` — into its own result struct through
  its first-argument pointer `%r15`, not through the element
  pointer `%r13`.
- Over all 63 window callers, the whole-FDE census finds 76 stores
  at the eight displacements through non-stack bases (all pinned
  in `records.json`). A linear register-provenance tracker —
  a register is marked when its value is data-dependent on an
  `imul $0xb0` / `imul $0xb8` product in the same body, propagated
  through `mov`/`lea`/`add`/`sub`, cleared by other writes and by
  calls for caller-saved registers — marks **none** of the 76 as
  element-derived, and no store at any displacement in
  `[0x40, 0xa0)` in the window has a marked base. The 76 are
  ordinary traffic of other structs sharing the offsets in other
  phases of those bodies.

So the fields are written before the consumption window, by
whoever builds the elements. That builder is **not** pinned here,
deliberately: the strides do not identify it. A decode-verified
census finds 589 genuine `imul $0xb8` rows in 226 FDEs binary-wide
(the fallback's own shape alone recurs in clone bodies over other
184-byte records), and `imul $0xb0` is likewise shared — stride
alone cannot separate this family's builder from unrelated ones.

## Layout record (what the bytes prove, without field names)

- Node presentation: element = `node + position × 0xb0`; the
  callee's eight offsets apply directly.
- Flat presentation: record = `base + index × 0xb8`; the search
  key sits at record `+0x0` (the fallback's compares), and the
  callee's element pointer is `record + 8`, so each field the
  callee reads at `+f` sits at record offset `f + 8`
  (`+0x48/+0x60/+0x68/+0x80/+0x88/+0x90/+0x98/+0xa0`).

## What the ratio measures (proven structure vs interpretation)

Proven by the pinned bytes (#2558, with the helper now traced):
the callee forms two u128 products of element field pairs
(`+0x40 × +0x58`, `+0x78 × +0x60`), divides them exactly by 10^14
through this helper (integer division, with a ceiling adjustment
on the first quotient), clamps the combined value against the
`+0x90`/`+0x98` fields with the per-arm `+0x80`/`+0x88` values,
and returns it divided by 10^14 as a double. So the return is a
14-decimal fixed-point ratio of products of element quantities,
bounded by two further element fields.

Interpretation, labelled as such: that shape is consistent with a
normalised rate-like quantity derived from two (value × scale)
pairs stored in the element — but the bytes do not name any field,
and this packet does not name them either. Naming them needs the
element builder, which the boundary above leaves open.

## Method

1. Resolve the slot from the artifact (section table → `.got`;
   `.rela.dyn` scan → one entry, addend `0x63efec0`; initialised
   qword read directly, zero).
2. Pin the helper by exact FDE extent, digest and all 67 rows;
   derive the contract by operand census (no memory operand, no
   call), branch-target closure, and the `div` guard structure.
3. Census slot references binary-wide by modrm position (every
   `mod=00/rm=101` position, target equation `p + 5 + k + disp32`
   for `k ∈ {0, 1, 2, 4}`), classify by the preceding opcode byte,
   and census direct `E8` calls to the body separately.
4. Re-verify the callee and its four callers against the #2558
   digests; re-derive its element loads and helper calls; pin the
   fallback and sibling bodies outright.
5. Census stores over the 63 #2542 caller FDEs (digest-verified
   first) with the provenance tracker described above; pin every
   store at the eight displacements with its body, base register
   and text.

## Boundaries and open questions

- The element builder (whoever writes the eight fields before the
  consumption window) remains unidentified; stride-based censuses
  cannot isolate it, as recorded above. A future lane needs a
  different discriminator (e.g. tracing the node/array allocation
  and insertion paths from the handle constructors).
- The helper's 305 slot references are census-level pins: the
  modrm positions and opcode classes are checked exactly, but
  only the callee's seven sites are decode-verified (in #2558).
- Still open behind this packet, unchanged from #2558: the other
  strides' layouts (0x40 from #2546; 0x30 / 0x10 / 0x14 / 0x48
  from #2552) and #2552's five unpinned per-layout fallback bodies
  (`0x4551810`, `0x4551c20`, `0x45585e0`, `0x24c9200`,
  `0x57f7210`).
- This packet pins evidence and contracts; it does not name the
  helper, the callee, or the element fields.
