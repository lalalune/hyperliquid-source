# RE-001-node115-lu-opt-hpa-sec-leaves: evidence

- Component ID: RE-001 node-115 control-tree leaves, opt children
  groups 11–15 (hpa_sec family).
- Target release and full SHA-256: node #115,
  `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- Claim status: observation (disassembly + file bytes + relocation
  addends). No runtime behaviour is claimed; `.data` values are
  file-initial only.
- Scope included and excluded: included — the five handler FDEs
  below, their node/slot resolution, their value loads, and the
  read-only contract shape. Excluded — the remaining 151 leaves,
  dispatcher internals, runtime `.data` values, and the
  `0x63cba10` caller FDE.

## Reproduce

Worktree `hl-wt-calls265-115`, branch `codex/re-004-calls265-115`,
base `05bc2de30`. Static analysis only; the binary was never
executed. Tool versions: system `objdump`, `readelf`, `python3`.

- `objdump -d --start-address=0x636f9e0 --stop-address=0x636fbf7
  artifacts/node/115/hl-node` (and likewise for the other four
  FDEs) regenerates each `.objdump.txt` exhibit up to the
  path-embedding file-format header line, which the verifier and
  tests strip before comparing.
- `.hex` exhibits are raw binary bytes sliced at file offset
  VA − 0x1000 (`.text` program-header mapping re-derived:
  PT_LOAD off=0x1418300 ↔ vaddr=0x1419300), not hex text.
- `.rela.dyn` addends were read from the section headers
  (offset 0x6be8, 60,723 entries total, 59,534 of type RELATIVE);
  `.data` file values were read at VA − 0x3000 (section
  addr 0x64efa20 ↔ file offset 0x64eca20).

## Evidence

Original addresses and coordinate system (VA/file offset), validated
boundaries, raw disassembly/data, callers/callees/indirect calls:

- Node resolution: opt children array `0x64de2e0`, 65 children,
  5-qword entries (stride 0x28), handler slot at entry offset +32.
  Group 11 node `0x64de498` → name `hpa_sec_nshards`, handler
  `0x636f9e0`; group 12 node `0x64de4c0` → `hpa_sec_max_alloc`,
  `0x636fc00`; group 13 node `0x64de4e8` → `hpa_sec_max_bytes`,
  `0x636fe20`; group 14 node `0x64de510` →
  `hpa_sec_bytes_after_flush`, `0x6370040`; group 15 node
  `0x64de538` → `hpa_sec_batch_fill_extra`, `0x6370260`.
  Each name comes from the node+0x08 RELATIVE addend and each
  handler from the node+0x20 RELATIVE addend; the group slot
  addend equals the handler in all five cases.
- FDE bounds from `.eh_frame` (PC-relative sdata4, CIE
  augmentation zR, encoding 0x1b): all five FDEs are 535 bytes
  (`0x636f9e0..0x636fbf7`, `0x636fc00..0x636fe17`,
  `0x636fe20..0x6370037`, `0x6370040..0x6370257`,
  `0x6370260..0x6370477`), consecutive with 9 bytes of padding
  between neighbours; the next FDE after the last is `0x6370480`
  (group 16, not claimed).
- Value loads (the only per-leaf difference): base lea to
  `0x64ffac0`, then `mov (%rdx),%rdi` (nshards),
  `mov 0x8(%rdx),%rdi` (max_alloc), `mov 0x10(%rdx),%rdi`
  (max_bytes), `mov 0x18(%rdx),%rdi` (bytes_after_flush),
  `mov 0x20(%rdx),%rdi` (batch_fill_extra). File qwords:
  0x4, 0x8000, 0x40000, 0x20000, 0x0 respectively.
- Contract shape (verified identical across all five by
  instruction-level diff modulo addresses and the struct offset):
  entry endbr64; `or 0x20(%rsp),%r9` (newlen|newp) → return 1 on
  nonzero; oldp==0 or oldlenp==0 → return 0; *oldlenp==8 → store
  value, return 0; otherwise short-read copy loop
  (n = min(*oldlenp, 8)) ending in `mov %rcx,(%r8)` (*oldlenp :=
  n) and `mov $0x16,%r11d` (return 0x16). Single ret per FDE;
  all jumps stay inside the FDE; the only out-of-FDE transfer is
  the `__stack_chk_fail` call on canary mismatch.
- Callers: whole-`.text` raw E8 scan finds 0 direct entries per
  leaf (a real direct call would appear as an E8 with an exact
  rel32 target; none targets any of the five handlers). All five
  are reached only by dispatcher indirect tail-call.
- Strict counts: 147 mnemonic lines per FDE (address + bytes field
  + tab + mnemonic starting with a lowercase letter; objdump
  byte-continuation lines excluded), matching across README,
  records.json, and the PR body. Total: 2675 bytes, 735 strict
  instructions.

## Implementation and comparison

Not applicable: this packet is an evidence/classification packet,
not an implementation. No Rust path is claimed. The verifier
(`tools/node115_lu_opt_hpa_sec_leaves.py`) and tests
(`tests/test_node115_lu_opt_hpa_sec_leaves.py`) are static byte
checks with tamper controls (hex flip, strict-count change,
injected overlap), run before trusting any green result.

## Results and limitations

- Verifier exit 0; own tests standalone (tamper cases run first,
  each confirmed to fail the verifier; clean temp copy passes).
- `make verify` exit 0; `make catalogue-check` exit 2 with the
  pre-existing `Stale catalogue: README.md` failure on the new
  base (no catalogue file touched by this packet).
- Full `make test` not attempted (584 test files, hours-long,
  VM-restart risk); no full-suite tally claimed.
- Unknown: runtime values of `.data` globals `0x64ffac0..0x64ffae0`;
  dispatcher internals; the remaining 151 leaves; the `0x63cba10`
  caller FDE.
- Next question: classify the next five leaves in tree order (opt
  children groups 16+, starting with metadata_thp handler
  `0x6370480` and retain handler `0x6370690`); or decode the
  largest bin_table_init caller FDE `0x63cba10` (10 sites).
  Packet #266 should pick one of these, not both, to stay light.
