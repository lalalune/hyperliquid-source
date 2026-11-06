# RE-001-node115-lu-opt-groups31-35-leaves: opt children groups 31–35

- Component ID: node-115 control-tree opt leaves, groups 31–35
- Target release and full SHA-256: artifacts/node/115/hl-node,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes)
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly + file bytes + .rela.dyn addends);
  runtime values unresolved (see limitations)
- Scope included and excluded: five leaf handlers only (two value leaves,
  three constant-return stubs). Dispatcher internals, getter family, and
  the bin_table_init caller FDE 0x63cba10 are excluded.

## Reproduce

Working directory: the worktree root. Static analysis only; the binary is
never executed.

- `sha256sum artifacts/node/115/hl-node` →
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Node/handler/name resolution: parse `.rela.dyn` (file offset 0x6BE8,
  24-byte entries; 60,723 entries total, 59,534 of type RELATIVE). For each
  opt child node N (array 0x64de2e0, 65 children, 5-qword entries), the
  handler address is the RELATIVE addend at N+0x20 and the leaf name is the
  NUL-terminated string at the RELATIVE addend at N+0x08.
- FDE bounds: parse `.eh_frame` (PC-relative sdata4 encoding, CIE
  augmentation zR, encoding byte 0x1b); do not scan for endbr64.
- Exhibits: `objdump -d --start-address=<s> --stop-address=<e>
  artifacts/node/115/hl-node`, header lines (blank + file-format) stripped
  in the stored exhibits; `.hex` files are the raw binary slice
  [VA−0x1000, VA−0x1000+size) for `.text` addresses.
- Verifier: `python3 tools/node115_lu_opt_groups31_35_leaves.py` (exit 0).
- Tests: `python3 tests/test_node115_lu_opt_groups31_35_leaves.py`.
- `make verify` exit 0 (559 evidence-packet manifests, 7169 entries);
  `make catalogue-check` exit 2, pre-existing Stale catalogue: README.md
  on the new base (no catalogue file touched by this packet).

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000 (re-derived from
program headers: PT_LOAD off=0x1418300 ↔ vaddr=0x1419300); `.data`
VA − 0x3000; `.data.rel.ro`/`.got` VA − 0x2000; `.rodata` VA as-is.
`.bss` starts at 0x64ffe40, so the zero leaf's 0x6511738 is a `.bss`
address; `.data` starts at 0x64efa20, so junk's 0x64ffb60 is a `.data`
address.

Value leaves (contract skeleton as packet #261's value leaves):

- opt/junk, node 0x64de7b8, FDE 0x6371f10..0x6372127 (535B, 147 strict):
  lea target 0x64ffb60 (`.data` qword, file value 0x0); write attempt
  (newp|newlen != 0) returns 1; exact-length read (cmp $0x8) stores the
  qword and returns 0; short read copies min(*oldlenp, 8) from a stack
  temp, sets *oldlenp, returns 0x16. One ret; one call, to
  `__stack_chk_fail` PLT 0x63f0d70; all jumps inside the FDE.
- opt/zero, node 0x64de7e0, FDE 0x6372130..0x63721b6 (134B, 36 strict):
  lea target 0x6511738 (`.bss` byte, runtime value not in file);
  movzbl load; exact-length read (cmp $0x1) stores the byte and returns
  0; short read returns 0x16. One ret; one call, to `__stack_chk_fail`
  PLT 0x63f0d70; all jumps inside the FDE.

Stub leaves (new shape in this run): each FDE is exactly 10 bytes —
endbr64 (4B), `mov $0x2,%eax` (5B), ret (1B). No frame, no canary, no
calls, no jumps, no memory access. All three stub `.hex` exhibits are
byte-identical (same 10 bytes); only the address column differs in the
objdump exhibits.

- opt/utrace, node 0x64de808, FDE 0x636c7b0..0x636c7ba (10B, 3 strict);
  next FDE 0x636c7c0 (6 int3 pad bytes).
- opt/xmalloc, node 0x64de830, FDE 0x6378090..0x637809a (10B, 3 strict);
  next FDE 0x63780a0 (6 int3 pad bytes).
- opt/experimental_infallible_new, node 0x64de858, FDE
  0x6377db0..0x6377dba (10B, 3 strict); next FDE 0x6377dc0 (6 int3 pad
  bytes).

Opt-children-array census (all 65 groups resolved via `.rela.dyn`):
each stub address is the handler slot of exactly one opt group (33, 34,
35) — the stubs are not shared between groups. Whole-`.text` raw E8
census: 0 direct call entries into any of the five handlers, so all
five are reached only by dispatcher indirect tail-call.

Disjointness: range-only collector over the merged tree plus packets
#183–#268 worktrees, deduplicated by real packet slug, census/cited-only
subtrees excluded; explicit non-overlap with packet #232's merged FDE
0x63b8820..0x63b8d85, packet #252's r28_wait 0x63ec890..0x63ec8a3, and
packet #215's handler FDE 0x63d9700..0x63d987b. The only prior mention of
0x6371f10 is packet #268's `next_fde_after_last` pointer (cited-only
metadata, not a claim) — it is this packet's group-31 handler, as #268's
next question invited.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this
packet; it is an evidence packet only (classification + exhibits +
static verifier + tests).

## Results and limitations

- 5 leaves classified; 131 of 204 static leaves remain unclassified.
- Runtime values unknown from the file: `.bss` byte 0x6511738 (zero),
  runtime `.data` qword 0x64ffb60 (junk, file value 0x0).
- The dispatcher-side meaning of the stubs' return value 2 is not
  decoded; only the observed behaviour (return 2, touch nothing) is
  claimed.
- Next question: classify opt children groups 36+ (starting with the
  FDE at 0x63721c0 — opt/tcache, group 36, node 0x64de880); or decode
  the largest bin_table_init caller FDE 0x63cba10 (10 sites). Packet
  #270 should pick one, not both, to stay light.
