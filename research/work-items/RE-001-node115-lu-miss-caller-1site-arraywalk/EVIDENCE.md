# Evidence: RE-001-node115-lu-miss-caller-1site-arraywalk

## Target

- Node: #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Base: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Window: FDE `0x635e2e0..0x635f315`, 4,149 bytes, 898 strict lines

## Method

Static analysis only: targeted `objdump -d
--start-address=0x635e2e0 --stop-address=0x635f315`, own `.eh_frame`
parse (135,313 FDEs), raw-`0xe8` census grouped by enclosing FDE,
and a reaching-definitions analysis over the window CFG for the
lu-miss `rcx` and the three second-handler `rsi` provenances
(noreturn PLT calls terminal; `cmov` is a conditional def). No node
execution.

## Findings

- Seventh packet of the lu-miss-caller frontier (callers of the
  lu-miss handler `0x63d9700` that do not call `bin_table_init`).
  A SHARED survivor: in both the 16-FDE lu-miss survivor list and
  the 18-FDE second-handler survivor list (survey
  `~/workspace/scratch-hl314survey/census.json`).
- Entry: `rdi` = input array base (saved `0x18(%rsp)`), `rsi` =
  element count (saved `(%rsp)`), `rdx` -> `r9`, `ecx` -> `r8d`;
  `rbx` = TLS-derived context base. No entry null guard.
- TLS flag `%fs:0x330` checked at `0x635e328`; init block at
  `0x635ecb7` calls helper `0x63ef8e0`.
- Size class: byte table `0x67277c0` + size table `0x6727a00` +
  flag `0x6713606`; thresholds `$0x1000`/`$0x3800`; no `$0xe7` gate.
- Walk: single, element-wise over the input array (`rbp` from
  `0x40(%rsp)` to `r13` = array base + 8 * (`r15` + `r9`)), key =
  `*rbp` in `rcx`; top index `(key >> 0x1a) & 0xf0`, high bits
  `key & 0xffffffffc0000000`, table `rbx + 0x1b0`.
- Extract: single shape — `shl`/`sar $0x10` + `and
  $0xffffffffffffff80` feeding helper `0x63be540` (once).
- Scan: single 8-slot move-to-front, table+`0x2b0` in `rbx`, key in
  `r10`; slot 0 at `0x635ecf0`, slots 1-7 in the shared loop at
  `0x635f0ed`; FOUR reversed-operand compares (slots 1, 2, 4, 5) —
  the first frontier window with any; exhaustion falls to the
  single lu-miss block at `0x635f2f1`.
- Lu-miss (1): call at `0x635f30b`; `rdi` = `rbx`, `rsi` = `.bss`
  `0x6511a00`, `rdx` = `lea 0x1b0(%rbx)`, `rcx` = element key
  (provenance: only reaching `rcx` definition is the walk-head
  load at `0x635ebb8`), `r8d` = 1, `r9d` = 0; rejoin `jmp
  0x635ebf9`.
- Second-handler (3): at `0x635ec8d` (`rsi` = node index
  `((0x50(%rsp) >> 0x14) - 1)`), `0x635ef3e` (`rsi` = 0),
  `0x635f24d` (`rsi` = `sched_getcpu()` result with the
  count-halving adjustment); all `rdi` = `rbx`, `rdx` = `lea
  0x64da4b0`.
- Dispatcher: #317 window once (`0x635e799`, `rdi` = entry `rdx`,
  `rsi` = entry `ecx`); `memset@plt` 15 times (unrolled slot-clear
  loop); `memcpy@plt`, `abort@plt`, `__stack_chk_fail@plt`,
  `sched_getcpu@plt` once each. 38 calls, 21 distinct direct
  targets, 0 indirect.
- Exit: single `ret` at `0x635e7eb`, `eax` = `r15` (element count).
- `bsr` 5, lock 0/0, jumps 131 (0 outside), 0 tail-jump exits.

## Verification

- Static verifier `tools/node115_lu_miss_caller_1site_arraywalk.py`:
  exit 0.
- Own unit tests
  `tests/test_node115_lu_miss_caller_1site_arraywalk.py`
  (tamper controls first): exit 0.
- `make verify`: exit 0 (559 evidence-packet manifests, 7159 entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation is declared here
  rather than hidden.

## Next question

Packet #321 decodes `0x63c9650..0x63c9c80` (1,584 bytes, 363 strict,
12 calls, 2 lu-miss sites at `0x63c9c29` and `0x63c9c76`, 0
bin_table_init sites, 0 second-handler sites, 1 ret at `0x63c9868`,
bsr 0 — the next surviving lu-miss caller after this packet,
verified by targeted objdump census against all prior exhibits; it
is a lu-miss-ONLY survivor, unlike this packet).
