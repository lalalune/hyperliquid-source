# RE-001-node115-lu-opt-groups47-51-53-54-55-leaves: five opt control-tree leaves

- Component ID: lu opt children-array leaves, groups 47, 51, 53, 54, 55
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes, artifacts/node/115/hl-node)
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly + file bytes); runtime values
  of .bss bytes and runtime values of .data slots are unresolved
- Scope included and excluded: the five handler FDEs listed below, their
  value slots, and the contract skeleton they share. Excluded: groups 48,
  49, 50, 52 (already claimed, see README), the intervening non-leaf FDE
  0x6373da0..0x6373e26, the dispatcher, the getter family, and the
  largest bin_table_init caller FDE 0x63cba10.

## Reproduce

Working directory: the packet worktree at upstream main 05bc2de30.
Binary: artifacts/node/115/hl-node (SHA-256 above; the verifier checks
size and hash before any other check). Static analysis only; the binary
is never executed. Coordinates: .text file offset = VA - 0x1000;
.data = VA - 0x3000; .data.rel.ro/.got = VA - 0x2000; .rodata = VA as-is.
Program-header re-derivation: PT_LOAD off=0x1418300 ↔ vaddr=0x1419300.
Exhibits: `objdump -d --start-address=<start> --stop-address=<end>`
on the binary, blank and file-format header lines stripped; .hex files
are the raw binary slices (VA - 0x1000). Strict counts use the regex
`^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]` (mnemonic must start with a
lowercase letter; byte-continuation lines excluded).

Node/handler resolution: opt children array 0x64de2e0, 65 children,
5-qword entries, handler slot at entry offset +32, name slot at entry
offset +8. Both slots were resolved via `.rela.dyn` addends (60,723
entries total, 59,534 of type RELATIVE; file slots are zero-filled, so
the addend is the authority). FDE bounds come from `.eh_frame`
(PC-relative sdata4 encoding, fixed 4-byte range fields).

## Evidence

Original addresses (VA) and validated FDE boundaries:

| leaf | node | handler FDE | bytes | strict |
| ---- | ---- | ----------- | ----- | ------ |
| opt/lg_extent_max_active_fit | 0x64dea38 | 0x63735a0..0x63737b7 | 535 | 147 |
| opt/prof_thread_active_init | 0x64dead8 | 0x6373af0..0x6373b76 | 134 | 36 |
| opt/lg_prof_interval | 0x64deb28 | 0x6373e30..0x6374047 | 535 | 147 |
| opt/prof_gdump | 0x64deb50 | 0x6374050..0x63740d6 | 134 | 36 |
| opt/prof_final | 0x64deb78 | 0x63740e0..0x6374166 | 134 | 36 |

Value slots and file values: lg_extent_max_active_fit loads u64 from
.data 0x64ffbe8 (file value 0x6, via `lea ... # 64ffbe8` +
`mov (%rdx),%rdi`, exact-size `cmp $0x8,%rcx`); lg_prof_interval loads
u64 from .data 0x64ffce8 (file value 0xffffffffffffffff, same shape);
prof_thread_active_init loads a byte from .data 0x64ffcf8 (file value
0x1, via `lea ... # 64ffcf8` + `movzbl (%rax),%esi`, exact-size
`cmp $0x1,%rdx`); prof_gdump loads a byte from .bss 0x6713605 and
prof_final loads a byte from .bss 0x6713604 (both via `movzbl
(%rax),%esi`; .bss is not in the file, so no file value is claimed).

Contract markers present in every FDE: `mov $0x1` (write attempt
returns 1), `mov $0x16` (short-read path returns 0x16), exactly one
`ret`, exactly one call (to `__stack_chk_fail` PLT 0x63f0d70), all
jump targets inside the FDE, and 0 direct E8 entries per handler in a
whole-`.text` raw E8 census. Normalized instruction-level diffs: the
two u64 FDEs are identical modulo lea displacement and jump targets,
as are the three byte FDEs.

Skip proof (exact FDE-range equality against prior records.json):
group 48 opt/prof 0x63737c0..0x6373846 = packet #261 (PR #2804) exhibit
opt_prof; group 49 prof_prefix 0x6373850..0x6373a5a and group 50
prof_active 0x6373a60..0x6373ae6 = packet #262 (PR #2810) exhibits;
group 52 lg_prof_sample 0x6373b80..0x6373d97 = packet #262 (PR #2810)
exhibit. The 153-byte gap between group 52's end and group 53's start
holds FDE 0x6373da0..0x6373e26, which no opt child node points at.

Analysis was complete for the five claimed FDEs (full disassembly
exhibited); no execution, no timeout, no range limitation beyond the
five windows.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is included in
this packet; the verifier and tests are static byte/disassembly checks
only. Comparison: exhibits regenerate byte-identically from the binary
(objdump regeneration + raw slice comparison); tamper controls (hex
flip, strict-count change, injected overlap, value-byte flip, byte-slot
flip) each fail the verifier, and a clean temp copy passes.

## Results and limitations

Metrics: 5 windows, 1472 bytes, 402 strict instructions; verifier exit
0; own tests all pass; make verify exit 0 (559 manifests, 7169
entries); make catalogue-check exit 2 (pre-existing Stale catalogue:
README.md, not a packet regression); full make test not attempted (584
files, hours-long, VM-restart risk). Remaining unknowns: runtime values
of the .bss bytes and .data slots, whether adjacent bytes/slots belong
to one struct, the dispatcher-side meaning of any value, and the 116
still-unclassified static leaves. Next question: classify the next five
leaves in tree order (opt children groups 56+, starting with the FDE at
0x6374170 — opt/prof_leak, group 56); or decode the largest
bin_table_init caller FDE 0x63cba10 (10 sites). Packet #273 should pick
one of these, not both, to stay light.
