# RE-006 node 115 join callee

## Scope

Packet `RE-006-node115-join-callee` answers the primary open question
left by `RE-006-node115-sibling-search` (#2542) and
`RE-006-node115-remaining-members` (#2552): the identity of the
indirect callee that the three 2816-byte join sites
(`0x2a89910`, `0x55a0bf0`, `0x55a16f0`) converge on through GOT slot
`0x64e7198`, called with `rdi` = the element pointer
`node + position × 0xb0` — the family's largest consumption class
(60 sites in #2542) depends on this one callee.

Everything is established against the Linux x86-64 node 115 artifact
(SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105,896,032 bytes). File offsets are resolved through the section
table throughout (VA − 0x1000 in `.text` / `.got` / `.rela.dyn`;
`.rodata` is identity-mapped).

## Short answer

- **The slot resolves statically.** The ELF is a static PIE
  (`ET_DYN`). Slot `0x64e7198` lies in `.got`
  (`0x64df458..0x64ee158`), its file-initialised content is zero,
  and it carries exactly one relocation: an `R_X86_64_RELATIVE`
  (type 8, symbol index 0) whose addend is `0x36a0d80`. The addend
  is the sole source of the target: **the callee is the body at
  `0x36a0d80..0x36a0fd6`, 598 bytes**, SHA-256
  `7bef359785703ce3ca6bbe09784c734204e78fc47f25759f4d14c08823b6dfc2`,
  an exact FDE start, pinned here by digest and by every one of its
  167 instruction rows.
- **Census: exactly four call sites binary-wide.** A scan of every
  `mod=00/rm=101` modrm position in the executable sections, testing
  the target equation `p + 5 + k + disp32` for trailing-immediate
  lengths `k ∈ {0, 1, 2, 4}`, finds exactly four references to the
  slot, all `k = 0`, all `call *disp(%rip)`, each verified as a
  genuine decode row in its digest-pinned caller FDE: the three
  joins (`0x2a89978`, `0x55a0c58`, `0x55a1758`) and a **fourth
  caller** at `0x2f0f6cc` in FDE `0x2f0f3b0..0x2f0f93a` (1,418
  bytes). At all four sites `rdi` is the join-produced element
  pointer (see below).
- **The callee is a pure function of the element pointer.** It
  saves `rdi` in `rbx` at entry (`0x36a0d8b`), reads exactly eight
  element fields and writes nothing through the pointer, makes no
  direct call, and returns an `f64` in `xmm0`: an integer built
  from two u128 products of element field pairs, scaled by 10^14,
  clamped against two further fields, and divided by 10^14.

## Method

1. Resolve the slot from the artifact, not from call-site shape:
   section table → slot inside `.got`; `.rela.dyn` scan → exactly
   one entry naming the slot, type `R_X86_64_RELATIVE`, addend
   `0x36a0d80`; the slot's initialised qword read directly (zero).
   In a static PIE the addend is applied verbatim, so the target is
   the addend.
2. Census references by modrm position: a rip-relative reference's
   modrm position `p` and its disp32 fix the target up to a
   trailing immediate, so enumerating every executable-section
   modrm position with `mod=00, rm=101` and testing
   `p + 5 + k + disp32 == 0x64e7198` for `k ∈ {0, 1, 2, 4}` is a
   complete census of references of every instruction form (call,
   jump, load, store, compare-with-immediate). Each hit is then
   verified as a real instruction in its caller's decode.
3. Pin the callee by exact FDE extent, SHA-256 digest and full
   instruction rows; derive its entry contract by operand census
   over those rows (element loads vs stores by AT&T operand
   position), call census, branch-target closure and immediate
   census, with the floating-point constants read from `.rodata`.
4. Pin argument provenance per call site with windows: for each
   join, the window from the sibling call through the indirect call
   (23 rows each); for the fourth caller, four phase windows. The
   three join callers' digests are byte-identical to the boundaries
   #2542 already pinned (cross-checked), as is the fourth caller's.

## The callee's entry contract

Body `0x36a0d80..0x36a0fd6` (598 bytes, one `ret` at `0x36a0f6a`,
no branch leaves the body):

- **Element reads — eight, on every path's union, none other.**
  Entry phase (every execution): `+0x40` (`0x36a0d8e`), `+0x58`
  (multiply operand, `0x36a0d95`), `+0x78` (`0x36a0dfb`), `+0x60`
  (multiply operand, `0x36a0dff`) — two field pairs, each forming a
  u128 product. Clamp phase: `+0x90` (`0x36a0eaa`), `+0x98`
  (`0x36a0eb1`). Per arm: `+0x80` (`0x36a0ec2`) or `+0x88`
  (`0x36a0f24`). **Element writes: none** — after the two arm loads
  overwrite `rbx` itself, no `[rbx+disp]` access occurs at all.
- **Calls — seven, all indirect, all through one slot.** Zero
  direct `E8` calls. The seven `call *disp(%rip)` sites
  (`0x36a0db4`, `0x36a0e1e`, `0x36a0e73`, `0x36a0eda`, `0x36a0f17`,
  `0x36a0f82`, `0x36a0fbf`) all name GOT slot `0x64dfaf8`, which
  itself carries exactly one `R_X86_64_RELATIVE` relocation, to
  `0x63efec0` (recorded here as a pinned fact; that body is not
  traced — the documented boundary of this packet). At every site
  the argument registers follow one contract: u128 numerator in
  `rdi`/`rsi`, u128 denominator in `rdx`/`rcx`, quotient returned
  in `rax`/`rdx` — the shape of an unsigned 128-bit division
  helper.
- **Scale.** The integer arithmetic is built around 10^14:
  `movabs` immediate `0x5af3107a4000` (10^14) at six sites and
  `0x5af3107a3fff` (10^14 − 1) at two clamp sites; the return
  conversion divides by the double at `0x459378`, whose bits are
  exactly 100000000000000.0, using the standard conversion
  constants at `0x450170` (2^52, 2^84) and `0x451210`
  (`0x43300000` / `0x45300000`). Reading: the callee returns
  `clamp(product-based integer, bounded by the +0x90/+0x98 fields
  with the +0x80/+0x88 arm values) / 10^14` as a double. Which two
  quantities the field pairs measure is a layout question, left
  open below.

## Argument provenance at the four sites

- **The three joins** (windows `join_0x2a89978`, `join_0x55a0c58`,
  `join_0x55a1758`): both arms converge on the single indirect call
  in `rdi`. Search arm: after the sibling call and the `cmpl $0x1`
  flag test, `imul $0xb0` on the record position plus the record
  node. Fallback arm: after the family fallback `0x4556410`, the
  bound check and clamp, `imul $0xb8` on the index, `lea` from the
  root, `add $0x8`. Exactly one `0xb0` scale, one `0xb8` scale and
  one `+0x8` bias per window — asserted by the tool.
- **The fourth caller** (FDE `0x2f0f3b0`) is itself a join-shaped
  consumer phase. Its third argument (`rdx`) is a handle pointer,
  kept in `r13`; the embedded search handle sits at `+0x58`
  (`[r13+0x58]` is loaded into `rbx` at entry and serves as the
  clamp bound; root `[r13+0x60]`, height `[r13+0x68]`, bound
  `[r13+0x70]`). It calls the sibling `0x35bf460` at `0x2f0f3fc`
  (record at `rsp+0x88`, key at `rsp+0x30`), forms the same element
  pointer on both arms (`imul $0xb0` from record node/position;
  fallback via `0x4556410` with `rdi = r13+0x58`, root +
  index × `0xb8` + 8), then **begins the callee's own computation
  inline** — its merge phase opens with the same clamp constant
  `0x5af3107a3fff` and reads the element's `+0x40`, `+0x58`,
  `+0x78`, `+0x60` in the callee's order — and only later passes
  `rdi = r13` into the call at `0x2f0f6cc`, stores the returned
  double at `[rsp+0x38]`, and re-reads `+0x40` / `+0x58` after the
  call. The uniform verdict stands: **at all four sites the
  argument is the join-produced element pointer.**

## Boundaries and open questions

- The helper body at `0x63efec0` (reached via slot `0x64dfaf8`) is
  identified by its relocation only; tracing it is the natural
  next step behind this packet, together with the question of what
  the callee's ratio measures.
- The 0xb0-byte element's field layout (which fields the eight
  offsets are) remains open, as do the other element strides'
  layouts (0x40 from #2546; 0x30 / 0x10 / 0x14 / 0x48 from #2552)
  and the five per-layout fallback bodies #2552 identified by call
  site only (`0x4551810`, `0x4551c20`, `0x45585e0`, `0x24c9200`,
  `0x57f7210`).
- This packet pins evidence and the entry contract; it does not
  name the callee or the helper.
