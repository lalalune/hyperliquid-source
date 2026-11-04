# RE-001-node115-lu-opt-groups21-25-leaves: bounded question

- Component ID: node-115 control-tree leaves, opt children groups 21–25
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`
  (105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (disassembly + file bytes); runtime values
  unresolved where the file cannot supply them
- Scope included: five leaf handlers in tree order after packet #266's
  groups 16–20; their read-only contracts and file-initial values
- Scope excluded: the remaining 141 leaves; dispatcher internals; the
  largest bin_table_init caller FDE `0x63cba10` (packet #266's other
  option, explicitly not taken); runtime `.bss`/`.data` values

## Reproduce

Static analysis only; the binary was never executed. Working directory:
the repository root. Tools: `objdump`, `readelf` (binutils), Python 3
(stdlib only).

- Binary identity: `sha256sum artifacts/node/115/hl-node` and size
  check (105,896,032 bytes).
- Node resolution: `readelf -r artifacts/node/115/hl-node` — RELATIVE
  entries (60,723 total `.rela.dyn` entries, 59,534 RELATIVE). The opt
  children array is `0x64de2e0` (65 children, 5-qword entries);
  group N's node is `0x64de2e0 + N*0x28`; handler slot at node+0x20,
  name slot at node+0x08. File slots are zero-filled, so the addend
  is the authority.
- FDE bounds: `.eh_frame` parse with PC-relative sdata4 encoding
  (CIE augmentation zR, encoding byte 0x1b). Sanity: packet #266's
  first FDE `0x6370480` = 525B and packet #265's FDE `0x636f9e0` =
  535B, both reproduced by the same parser.
- Coordinates: `.text` file offset = VA − 0x1000 (program headers:
  PT_LOAD off=0x1418300 ↔ vaddr=0x1419300); `.data` = VA − 0x3000;
  `.data.rel.ro`/`.got` = VA − 0x2000; `.rodata` = VA as-is.
- Exhibits: `objdump -d --start-address=<s> --stop-address=<e>` per
  window; `.hex` files are raw binary slices, not hex text.
- Gates: `python3 tools/node115_lu_opt_groups21_25_leaves.py` (exit
  0), `python3 tests/test_node115_lu_opt_groups21_25_leaves.py`
  (standalone), `make verify` (exit 0), `make catalogue-check`
  (exit 2, pre-existing `Stale catalogue: README.md` on the new
  base). Full `make test` is NOT attempted (584 test files,
  hours-long, VM-restart risk); no full-suite tally is claimed.

## Evidence

Original addresses and coordinate system: VAs as listed in the
README; `.text` VA − 0x1000, `.data` VA − 0x3000, `.rodata` VA
as-is. FDE bounds validated by `.eh_frame`, not endbr64 scanning.

Leaf resolution (node → name addend → handler addend):

| group | node | name addend → string | handler addend |
| ----- | ---- | -------------------- | -------------- |
| 21 | 0x64de628 | 0x43245b → oversize_threshold | 0x6370f30 |
| 22 | 0x64de650 | 0x43242d → mutex_max_spin | 0x6370d10 |
| 23 | 0x64de678 | 0x4467c0 → background_thread | 0x6371150 |
| 24 | 0x64de6a0 | 0x4375bd → max_background_threads | 0x63711e0 |
| 25 | 0x64de6c8 | 0x4343ad → dirty_decay_ms | 0x6371400 |

Contract (all five, same skeleton as packet #261's value leaves):
entry `endbr64`, `sub $0x18,%rsp`, stack canary, `mov $0x1` return
preset, `or 0x20(%rsp),%r9` (newp|newlen) → nonzero jumps to the
return-1 path; oldp==0 or oldlenp==0 → return 0; *oldlenp==size
stores the value and returns 0; any other *oldlenp takes the
short-read path (n = min(*oldlenp, size) bytes copied from a stack
temp, *oldlenp set to n, return 0x16). Single ret per FDE; all
jumps stay inside the FDE; the only out-of-FDE transfer is the
`__stack_chk_fail` call (0x63f0d70) on canary mismatch.

Value loads:

- oversize_threshold: `lea 0x64ffb70,%rdx; mov (%rdx),%rdi` —
  u64 at `.data` 0x64ffb70, file-initial 0x800000 (8388608).
- mutex_max_spin: `lea 0x64ffc98,%rdx; mov (%rdx),%rdi` —
  u64 at `.data` 0x64ffc98, file-initial 0x258 (600).
- background_thread: `lea 0x6711b30,%rax; movzbl (%rax),%esi` —
  byte at `.bss` 0x6711b30, runtime value not in the file; size 1
  (cmp $0x1).
- max_background_threads: `lea 0x64ffbc8,%rdx; mov (%rdx),%rdi` —
  u64 at `.data` 0x64ffbc8, file-initial 0x1000 (4096).
- dirty_decay_ms: `lea 0x64ffb78,%rdx; mov (%rdx),%rdi` —
  u64 at `.data` 0x64ffb78, file-initial 0x2710 (10000).

The four u64 FDEs are instruction-identical modulo the value-load
lea displacement and intra-FDE jump targets (normalized
instruction-level diff; the only differing line is the lea).
Whole-`.text` raw E8 scan (exact rel32 targets) gives 0 direct
entries into each handler FDE: all five are reached only by
dispatcher indirect tail-call.

Paddings: mutex_max_spin end 0x6370f27 → oversize_threshold start
0x6370f30 (9B); oversize_threshold end 0x6371147 →
background_thread start 0x6371150 (9B); background_thread end
0x63711d6 → max_background_threads start 0x63711e0 (10B);
max_background_threads end 0x63713f7 → dirty_decay_ms start
0x6371400 (9B); dirty_decay_ms end 0x6371617 → next FDE
0x6371620 (9B, group 26, not claimed).

Analysis was complete for the five claimed windows; no timeout or
range limit applies to them.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is included
in this packet. The packet is evidence only (disassembly exhibits,
records, static verifier, tests).

## Results and limitations

- Claimed: 5 windows, 2274 bytes, 624 strict instructions
  (147 + 147 + 36 + 147 + 147).
- Verifier exit 0; own tests standalone, tamper controls run
  first (hex flip, strict-count change, injected overlap each fail
  the verifier; clean temp copy passes).
- `make verify` exit 0 (559 manifests, 7169 entries: base 7154 +
  this packet's 15 MANIFEST entries). `make catalogue-check`
  exit 2, pre-existing `Stale catalogue: README.md`, not a packet
  regression.
- Unknown: runtime values of the `.bss` byte and of the `.data`
  qwords; the remaining 141 leaves; dispatcher internals; the
  `0x63cba10` caller FDE.
- No gate is requested beyond the packet's own verifier, tests,
  and `make verify`.

Next question: classify the next five leaves in tree order (opt
children groups 26+, starting with the FDE at `0x6371620`); or
decode the largest bin_table_init caller FDE `0x63cba10` (10
sites). Packet #268 should pick one of these, not both, to stay
light.
