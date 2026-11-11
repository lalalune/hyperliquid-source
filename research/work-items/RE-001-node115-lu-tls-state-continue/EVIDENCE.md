# RE-001-node115-lu-tls-state-continue: TLS state refresh, global list helpers, interval-value writer census, slow paths, five more leaves

- Component ID: RE-001-node115-lu-tls-state-continue (packet #260)
- Target release and full SHA-256: artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390 (fetched and confirmed before analysis; the main clone HEAD stays untouched at 2993e46)
- Claim status: observation for every exhibited byte range and census count; inference only where explicitly marked (global identities, callee roles); unresolved items are listed at the end
- Scope included and excluded: included — the 14 exhibited windows, the call-site censuses, the interval-value writer census, and the 5 leaf classifications. Excluded — the 176 remaining leaves, the bin-setup and teardown-body callees (named only), the interval consumer FDE 0x63c41c0 (cited only), and any runtime `.bss` value.

## Reproduce

Static analysis only; the node binary was never executed.

- Worktree: `~/workspace/hl-wt-calls260-115`, branch `codex/re-004-calls260-115`, from origin/main at the commit above.
- FDE bounds: `readelf --debug-dump=frames-interp` on the binary (the `.eh_frame` uses PC-relative sdata4 FDE encoding, CIE augmentation zR, encoding byte 0x1b; a naive absolute parse returns garbage — packet #246's lesson).
- Disassembly: `objdump -d --start-address=... --stop-address=...` per window; coordinate rule `.text` file offset = VA - 0x1000, `.rodata` = VA as-is, `.data.rel.ro`/`.got` = VA - 0x2000. `.bss` has no file bytes.
- Call-site censuses: raw E8/E9 byte scan over the `0x6300000..0x6500000` code window, with every hit verified by disassembling its enclosing FDE; a full-file raw scan at build time gave identical counts for every target (no sites outside the window).
- Interval-value references: capstone disassembly of every FDE in the
  binary (135,313 FDEs, 18,827,581 instructions), collecting RIP-relative
  operands; neighbouring-base lea tracking used linear FDE walks with
  register-overwrite and call-clobber rules (caller-saved registers cleared
  on call).
- Instruction counts are STRICT mnemonic lines: a line matching address + bytes field + blank + mnemonic. Objdump byte-continuation lines (a lone byte with no mnemonic) are excluded — a first regex that counted them was caught and fixed during this packet's build.
- Tool versions: system objdump/readelf, python3 with capstone 5.0.7 for analysis only (the shipped verifier uses byte reads only, no capstone, no objdump).

## Evidence

### TLS state refresh (0x63ef5e0..0x63ef640, full FDE)

Raw bytes in `tls_state_refresh.hex`; disassembly in `tls_state_refresh.objdump.txt`.
Entry reads `ctx+0x330` into `%esi`. `cmp $2,%sil; ja` splits states > 2
(straight to the `xchg` with the value unchanged) from states <= 2 (new-state
computation). The new state is 1 when the gate-neighbour byte `0x64ffab0` is
nonzero, or `ctx+0` is zero, or `ctx+1` is positive (signed `jle` to the
global path); otherwise it is (`global 0x6728880` != 0) via `setne`. The
`xchg %sil,0x330(%rdi)` installs the new state; an old state of 2 loops to
re-read, any other old state falls through to `jmp 0x63eec10` at `0x63ef625`.
This confirms packet #259's tail-call claim by direct instruction read.

### Global list insert (0x63ef410..0x63ef4ed, full FDE)

`movups` self-links the node (`0xc8`/`0xd0` := ctx). `pthread_mutex_trylock`
on `0x67288e0`; the contention arm calls `0x63bf680` with record base
`0x67288a0` (lea at `0x63ef4d8`), then sets the contended byte `0x6728908`
:= 1 and retries at the counter block. Counters `0x67288d8` (every entry)
and `0x67288c8` + last-context `0x67288d0` (on context change only). The
splice block links ctx after the head slot `0x6728910` (empty list: head :=
ctx). The tail clears `0x6728908` := 0 and tail-jumps to
`pthread_mutex_unlock`. The only `E8` site is the TLS helper's call at
`0x63ef7a5`; the only `E9` site is list_reset's tail-call at `0x63efd14`.

### Global list reset (0x63efce0..0x63efd19, full FDE)

Lock helper `0x63bf970` with `rsi` = record base `0x67288a0`, then
`movq $0,0x6728910` (head cleared), then `cmpb $2,0x330(%rbx); jbe` to the
tail-call to list_insert. Sole `E8` caller `0x6350002`.

### Slow paths

- Disable (`0x63ed070..0x63ed089`, full FDE): `cmpb $0,(%rdi)`; zero returns,
  nonzero tail-jumps to `0x63ec900` with `rsi` = `ctx+0x358`.
- Enable head (`0x63ed090..0x63ed167`): loads `0x6728858`/`0x6728860`, applies
  the `0x3800`/`0x1000` caps, computes the aligned size, and starts the size
  table walk (`0x67277c0`, `0x6727a00`). The rest of the 2002B FDE is
  characterized only by its verified whole-FDE jump census (no jump leaves
  the FDE) and its call-target table (see records.json); the single `ret`
  is at `0x63ed350` and the stack-check failure call at `0x63ed85d`.

### Interval-value reader (0x63c3a90..0x63c3af2, full FDE)

`cmpq $0,0x6712440` then `cmpb $0,0x67125d0`; either zero returns. Otherwise
`r9` = `[0x67125e8]` (limit), `rcx` = `[0x67125e0]` (counter), `r8` =
`rsi + rcx`; if `r8 >= r9` the value is reduced modulo `r9` (`div`) before
the `lock cmpxchg` retry loop on `[0x67125e0]`; after a successful CAS,
`r8 < r9` returns, else the function tail-jumps to `0x63c3990`.

### Teardown gate and destructor registration

- Gate head (`0x63ef810..0x63ef830`): `movzbl 0x330(%rdi)`; `(1 << cl) &
  0x2b`; zero returns. Passing states are exactly 0, 1, 3, 5.
- Registration window (`0x63efbd3..0x63efbe6`): `lea rsi, 0x63ef810`,
  `lea rdi, &0x672891c`, `call pthread_key_create@plt` (the PLT name is
  printed by objdump itself). The enclosing FDE then sets `0x6728918` := 1
  and tail-jumps to the slow path `0x63ef8e0` when the current context's
  state byte is nonzero. This is the gate's only reachability: it has zero
  direct call sites.

### Writer census for 0x6712440

Direct references in the full binary: 27 RIP-relative references in
`0x6712400..0x6712480`, of which exactly 4 touch `0x6712440` (see
records.json for the full table). The only store is `0x63c417e` in the
latch FDE claimed by packet #258; its guards and value formula were
re-read from that FDE during this packet (prof byte nonzero,
`[0x64ffce8]` >= 0 signed, value `1 << cl`). The latch's sole caller is
`0x634eea7` in packet #257's request-init FDE. Indirect-offset tracking
over the complete set of 15 neighbouring-base lea sites found 0 stores.
The scan's scope limit is stated in the README: FDE-covered code only; a
store through a spilled/reloaded pointer or across non-linear control flow
would escape the tracking method, though no direct RIP-relative store
exists anywhere in the binary's FDE-covered code.

### Leaves

Each leaf FDE is exhibited in full; the classification logic is the handler
body itself:

- `opt/abort` (`0x636ec40..0x636ecc6`): loads the flag byte at `0x651174d`
  (.bss, runtime-filled); the `or newlen, newp; jne` epilogue returns 1 on
  any write attempt — the same shape packet #259 documented for
  `prof/interval` ("newp|newlen nonzero returns 1").
- `config/debug` (`0x6378570..0x63785ee`): identical shape, but the read
  value is the constant 0 written to the stack slot (`movb $0,0x7(%rsp)`),
  not a global load — a build-time constant.
- `experimental/utilization/query` (`0x6376c90..0x6376cfe`): validates
  newp present, newlen == 8, `*oldlenp` == `0x30` (all else `0x16`), then
  calls `0x63bc730` with oldp-derived field pointers and the index from
  `*newp`; returns 0. No global is stored.
- `tcache/flush` (`0x6377900..0x6377946`): `or oldp, oldlenp; jne` returns 1
  when any output slot is given; newp missing or newlen != 4 returns `0x16`;
  otherwise the u32 index from `*newp` goes to `0x63ee1f0`.
- `prof/thread_active_init` (`0x636dab0..0x636db74`) + setter head
  (`0x63c3f60..0x63c3fa7`): the read value is the prof byte itself when it
  is 0, else getter `0x63c3ee0`'s return; the write arm returns 2 when the
  prof byte is 0 and `0x16` on newlen != 1, and otherwise calls setter
  `0x63c3f60`, whose head shows the mutex `0x6712520` trylock, the
  counters, and the store of the new byte to `0x6712550`.

## Implementation and comparison

Not applicable: this packet contains no reconstructed implementation, only
static observations. No source mapping is claimed; symbol names are absent
(the binary's internal labels all render as a single placeholder), and PLT
names are used only where objdump prints them (`pthread_key_create`,
`pthread_mutex_trylock`, `pthread_mutex_unlock`, `__stack_chk_fail`).

## Results and limitations

- 14 exhibits, 1470 bytes, 367 strict lines; verifier exit 0; unit tests
  10/10; `make verify` exit 0; `make catalogue-check` result reported
  honestly in the PR body (pre-existing `Stale catalogue: README.md`
  failure on this base, not a packet regression).
- Full `make test` was not attempted (584 test files on this base; a full
  run takes hours and risks a VM restart). No full-suite tally is claimed.
- Disjointness: claimed ranges are disjoint from packets #183–#259 by the
  range-only collector (see the verifier); the merged tree was checked for
  directory-name collisions (slug `lu-tls-state-continue` is new).
- Unresolved: the 176 remaining leaves; the bin-setup and teardown-body
  callees; the interval consumer FDE; the identities of globals `0x6728880`,
  `0x64ffce8`, and the gate-neighbour byte `0x64ffab0`.
- Next question: next value-family leaf batch (`opt/prof`, `opt/tcache`,
  `config/stats`, `thread/allocated`, `stats/allocated`); decode the
  enable-slow-path bin-setup callees (`0x63ec4c0`, `0x63d9700` first);
  decode the interval-value consumer FDE `0x63c41c0` and the teardown-gate
  body callees.
