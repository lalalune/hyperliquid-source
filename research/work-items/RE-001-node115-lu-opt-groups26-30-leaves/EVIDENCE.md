# RE-001-node115-lu-opt-groups26-30-leaves: bounded question

- Component ID: RE-001 node-115 control-tree leaves, opt children groups 26–30
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`
  (105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (leaf contracts, FDE bounds, value loads);
  inference (tree order = node order); unresolved (runtime values,
  struct identity of the 0x6727770/0x6727780/0x672778b addresses)
- Scope included and excluded: included — 5 leaf FDEs in tree order
  after packet #267; excluded — the remaining 136 leaves, the
  getter family, dispatcher internals, and bin_table_init caller
  FDE `0x63cba10`.

## Reproduce

Worktree `~/workspace/hl-wt-calls268-115`, branch
`codex/re-004-calls268-115`, base `05bc2de30`. Static analysis
only; the binary was never executed. Tools: `objdump` (GNU
binutils, system version), `readelf`, `python3` (system version).
Coordinate system: `.text` file offset = VA − 0x1000 (re-derived
from program headers: PT_LOAD off=0x1418300 ↔ vaddr=0x1419300);
`.data.rel.ro`/.got = VA − 0x2000; `.rodata` = VA as-is;
`.data` = VA − 0x3000. RELATIVE `.got` slots are zero-filled in
the file — handler/name resolution uses `.rela.dyn` addends
(60,723 entries total, 59,534 of type RELATIVE).

Commands (run from the worktree root):

- `objdump -d --start-address=0x6371620 --stop-address=0x6371837
  artifacts/node/115/hl-node` (and likewise for the other four
  FDEs) — exhibits are the raw bytes of exactly these ranges.
- `python3 tools/node115_lu_opt_groups26_30_leaves.py` — static
  verifier, exit 0.
- `python3 tests/test_node115_lu_opt_groups26_30_leaves.py` —
  standalone tests, all pass.
- `make verify` — exit 0; `make catalogue-check` — exit 2 with
  the pre-existing `Stale catalogue: README.md` failure.

## Evidence

Leaf resolution: opt children array `0x64de2e0`, 65 children,
5-qword entries (stride `0x28`), handler slot at entry offset
+32 (node+0x20), name at node+0x08. Group 26 node `0x64de6f0`
(= array + 26×0x28); groups 27–30 follow at +0x28 each. Each
node+0x20 slot holds exactly one RELATIVE addend equal to the
handler address; each node+0x08 addend resolves (`.rodata` VA
as-is) to the leaf name. FDE bounds come from `.eh_frame`
(CIE augmentation zR, FDE encoding 0x1b = pcrel sdata4), not
from endbr64 scanning; every handler address is an exact FDE
start, and the five FDEs are consecutive (paddings 9/10/6/9/6
bytes; next FDE after the last is `0x6371f10`, group 31).

Value loads (hand-verified against the disassembly):

- muzzy_decay_ms: `lea 0x6711a88; mov (%rdx),%rdi` — qword
  AT `.bss` 0x6711a88, stored to the stack temp, then to oldp
  on the exact-length path.
- stats_print: `lea 0x672778b; movzbl (%rax),%esi` — byte AT
  `.bss` 0x672778b, stored to the stack temp byte, then to
  oldp on the exact-length path.
- stats_print_opts: `lea 0x6727780; mov %rdx,(%rsp)` then
  `mov %rdx,(%rax)` — the ADDRESS itself is the value (no
  dereference of 0x6727780 anywhere in the FDE).
- stats_interval: `lea 0x64ffd00; mov (%rdx),%rdi` — qword AT
  `.data` 0x64ffd00; file bytes at offset 0x64fcd00 read
  `0xffffffffffffffff`.
- stats_interval_opts: `lea 0x6727770; mov %rdx,(%rsp)` then
  `mov %rdx,(%rax)` — the ADDRESS itself is the value (no
  dereference of 0x6727770 anywhere in the FDE).

Contract skeleton (all five, verified in each FDE head):
write attempt (newp|newlen != 0, tested via `or 0x20(%rsp),%r9`
then `jne` to the return-1 path) returns 1 without touching
memory; read with oldp==0 or oldlenp==0 returns 0; read with
*oldlenp==size stores the value and returns 0; any other
*oldlenp takes the short-read path (n = min(*oldlenp, size)
copied from the stack temp, *oldlenp := n, return 0x16).
Whole-`.text` raw E8 scan gives 0 direct entries per handler
address. Each FDE has exactly one `ret` and exactly one call
(`__stack_chk_fail` PLT `0x63f0d70`); all jump targets stay
inside the FDE (checked by the verifier).

## Implementation and comparison

Not yet implemented/measured — this packet is evidence only;
no Rust reconstruction is claimed.

## Results and limitations

- Claimed: 5 windows, 2248 bytes, 622 strict instructions
  (147 + 36 + 146 + 147 + 146).
- Verified: verifier exit 0, tests all pass, MANIFEST
  `sha256sum -c` all 15 entries OK, `make verify` exit 0,
  `make catalogue-check` exit 2 (pre-existing, not a
  regression).
- Unknown: runtime values of all `.bss` globals and of the
  `.data` qword at `0x64ffd00`; whether `0x6727770`,
  `0x6727780`, and `0x672778b` belong to one struct.
- Next question: classify the next five leaves in tree order
  (opt children groups 31+, starting with the FDE at
  `0x6371f10`); or decode the largest bin_table_init caller
  FDE `0x63cba10` (10 sites). Packet #269 should pick one of
  these, not both, to stay light.
