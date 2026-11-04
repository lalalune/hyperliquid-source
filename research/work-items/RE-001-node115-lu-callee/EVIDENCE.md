# RE-001-node115-lu-callee: the shared callee past its gate

- Component ID: RE-001-node115-lu-callee
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all decoded control flow, argument
  shapes, census, and FDE bounds below; inference only where marked
  (role labels such as "release" / "repurpose" / "statistics" describe
  observed argument and accounting shapes, not proven upstream
  semantics); unresolved items are listed, not filled in.
- Scope included and excluded: included — callee FDE
  `0x63c1030..0x63c1360` past the `#209` entry gate, the mode flag
  computation, the acquisition loop, the node walk's two paths,
  the exit accounting and exit protocol, selector FDE
  `0x63b2630..0x63b2850` including the base comparison, and the
  census of both functions. Excluded — internals of
  `0x63b3080`, `0x63b3c00`, `0x63b3b00`, `0x63b0780`,
  `0x63b0560`, `0x63b1b60`, `0x63adb50`, `0x63ae980`,
  `0x636b340`, `0x63b2c40`, `0x63a9750`, and every item in the
  README's unresolved list.

## Reproduce

Worktree `~/workspace/hl-wt-calls210-115`, branch
`codex/re-004-calls210-115`, from `origin/main` of the main
clone (HEAD untouched). Static only: `objdump -d
--start-address=… --stop-address=… artifacts/node/115/hl-node`
for the FDE ranges, `objdump --dwarf=frames` for FDE bounds,
`readelf -SW` for section coordinates (`.text` VA
`0x1419300`, file offset `0x1418300`, so `.text` file offset
= VA − 0x1000), and a byte scan of `.text` plus a
`.rela.dyn` addend scan for the census. No node execution,
no network, no writes outside the worktree packet dir,
`tools/`, `tests/`, and scratch `~/workspace/scratch-hl210/`.
Tool versions: system `objdump`/`readelf`, python3.

## Evidence

Original addresses and coordinate system (VA; `.text` file
offset = VA − 0x1000). FDE bounds from `.eh_frame`:
callee `0x63c1030..0x63c1360` (816B), selector
`0x63b2630..0x63b2850` (544B).

Callee argument map (SysV + stack): thread rdi, ref rsi,
C rdx, arg4 rcx, arg5 r8, mode r9d, base stack arg7
(`0x80(%rsp)` in-frame), amount stack arg8 (`0x88(%rsp)`).
Entry gate per `#209` (latch `[C+0x70]`, amount test) is
cited, not re-claimed. Past the gate: ref → rbp, thread →
rbx, arg5 → r12, mode → r15d, arg4 → `0x8(%rsp)`,
C → `0x10(%rsp)`, `C+0x40` → `0x20(%rsp)`; `[C+0x68] = 0`;
`pthread_mutex_unlock@plt` at `0x63c1090`.

Acquisition loop (`loop_call` exhibit, `0x63c10a8..0x63c10c2`,
26B/6 strict): pool `(%rsp)` from `0x636b340` at
`0x63c109c`; call `0x63b2630` at `0x63c10bd` with
`(thread, ref, pool, arg5, base)`; NULL → `0x63c1278`;
non-NULL → self-link write (`movups` of duplicated rax to
`[block+0x40]`), splice into the circular list at
`+0x40`/`+0x48`, `pages += [block+0x10] >> 12`, loop while
`pages < amount` (`0x63c111c`, `0x63c1233`).

Mode flag (`callee_mode` exhibit, `0x63c1133..0x63c1146`,
19B/5 strict): `xor r11d`; `test %r15b` (mode); `je
0x63c1340` where `[ref+0xec88]` is loaded
(`4c 8b bd 88 ec 00 00`) and `setne %r11b` (`41 0f 95 c3`)
gives r11 = field-nonzero; mode != 0 keeps r11 = 0. Saved
to `0x2c(%rsp)` at `0x63c115c`.

Walk (per node): count += 1, pages += `[node+0x10] >> 12`;
unlink via the `+0x40`/`+0x48` surgery at `0x63c1241`
(skipped when `[node+0x40] == node`, which also ends the
walk via `xor ebp` at `0x63c11b2`). Path selection:
`cmpl $1, 0x4be0(%r13)` at `0x63c11cd` (r13 = arg5) and
the saved r11 flag at `0x63c11d7`; probe call
`0x63b3c00` at `0x63c11ef` (`test %al; jne` release on
nonzero); repurpose call `0x63b3b00` at `0x63c1215`
with `ref+0x4c28` as arg4; release call `0x63b3080` at
`0x63c1194` with page-aligned size in r8
(`and $0xfffffffffffff000` at `0x63c11c3`).

Exit accounting (`callee_stats` exhibit,
`0x63c1300..0x63c1326`, 38B/7 strict): `lock addq $1`
to arg4+0x0, `lock add` node count to +0x8, `lock add`
total pages to +0x10, `lock sub` released bytes from
`[ref+0xf310]+0x38`. Exit protocol (`callee_tail`
exhibit, `0x63c1286..0x63c12ba`, 52B/12 strict):
`pthread_mutex_trylock@plt` at `0x63c128f`; success →
`C+0x38`++, owner tracking `C+0x30`/`C+0x28`, latch
`[C+0x70] = 0`; failure → wait helper `0x63bf680` at
`0x63c12d3`, `[C+0x68] = 1`, then the same success path.

Selector (`base_gate` exhibit, `0x63b26d0..0x63b26eb`,
27B/6 strict): arg5 mutex trylock at `0x63b266e`
(same wait helper / flag protocol); chain head
`[arg5+0x2610]` with `[arg5+0x4bc8]` fallback
(`0x63b26b0` / `0x63b27c0`); sum from two `0x63b0510`
loads (`0x63b26cb`, `0x63b26d8`); `cmp %rbp, 0x18(%rsp)`
+ `jae` NULL at `0x63b26e0`/`0x63b26e5`; kind compare
`cmpl $2, 0x4be0(%r12)` at `0x63b2761` selecting
`0x63ae980` (> 2, plus gated global decrement at
`0x67121d8`) versus `0x63adb50` (<= 2); flag byte
`[arg5+0x4be8]` test at `0x63b26f6`; `0x63b1b60` call
with out-flag, retry via `0x63b0560` + head reload.

Census: byte scan of all of `.text` for E8/E9 rel32 and
LEA rip-relative targets, plus a 60,723-entry `.rela.dyn`
addend scan. Callee `0x63c1030`: E8 at `0x63c1989`
(workerB), `0x63c1a89` (workerA mode-0), `0x63c1ae1`
(workerA `== 0`); E9 0, LEA 0, GOT 0. Selector
`0x63b2630`: E8 at `0x63c10bd` (callee loop),
`0x63c1cad` (FDE `0x63c1c60..0x63c1cc5` drain loop:
`0x63b2630(thread, ref, pool, ref+0x9818, 0)` until NULL,
each block to `0x63b2c40`); E9 0, LEA 0, GOT 0. Each
census site was confirmed by disassembly, not by the
byte scan alone.

Analysis was complete for the two FDEs' control flow at
the claimed level (argument shapes, branches, calls);
callee bodies beyond the named calls were not entered.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is
claimed by this packet; no build, no equivalence claim.
The verifier and tests below check the evidence bytes
against the target binary only.

## Results and limitations

- Static verifier `tools/node115_lu_callee.py`: exit 0
  (5 exhibits, 162 bytes, 36 strict mnemonics, key-byte
  sites, census, FDE bounds, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_callee.py`: 8/8 pass.
- `make doctor`: analysis_ready true.
- `make verify`: exit 0.
- `make catalogue-check`: exit 0.
- `make test`: 77 files attempted, 1 failed — the single
  failure is the pre-existing test_node115_catalogue
  Errno 18 cross-device-link error; this packet's file
  passes 8/8.
- Limitations: role labels (release / repurpose /
  statistics / pool / block) are descriptive of observed
  shapes; the bodies of the nine named callees, the
  `[ref+0xec88]` writer, the `[ref+0xf310]` object's
  identity, the arg4 record's consumer, the sub-page edge,
  and the `0x63b0560` retry mechanism remain open.
  No earlier verdict changes; `#209` confirmed in full
  and extended as the README states.

Next question: decode the release function `0x63b3080`
end to end — what it does with (thread, ref, pool, node,
page-aligned size), and what happens to the node
afterwards.
