# RE-001-node115-lu-nextnode: the node #115 lu next-node call

- Component ID: RE-001-node115-lu-nextnode
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (fetch-confirmed unmoved before analysis)
- Claim status: observation for all excerpt and key-byte claims; inference for the overflow-rotation mechanics (read directly from the swap instruction sequence); unresolved for the two detour callees' internals (see below)
- Scope included and excluded: included — thunk `0x63ae260`, worker `0x63adf40`, sibling thunk `0x63ae280` (census + key bytes only), the worker's gates and join call. Excluded — `0x63d9880` (thread == 0 detour), `0x63d9700` (miss handler), `0x63adb50` (join), `0x63b0780`, `0x63b1810`, `0x63b0560`, `0x63c1c40`, `0x63b2e60`, `0x63aa7d0`, `0x63b3c00`/`0x63b3b00`, `0x63a9750`, the C-0x80 divisor source, entry+8 condvar waiters, the runtime method pointees, `0x51e8720`, `0x5a50a10`/`0x5a4d200`, `0x51f3e20`/`0x57ec1b0`, `0x1680cab` — all still open, none decoded here.

## Reproduce

Working directory: a fresh worktree of upstream main `8fd8db6` (local branch
`codex/re-004-calls214-115`). Commands: `objdump -d --start-address --stop-address`
for the five excerpts; `objdump --dwarf=frames` for FDE bounds;
`python3 tools/node115_lu_nextnode.py` for the full static check (exit 0);
`python3 -m pytest tests/test_node115_lu_nextnode.py -q` (8 tests, see below);
`make verify`, `make catalogue-check`, `make test` for the suite.
Tool versions: system `objdump`/`readelf` (binutils as installed; old readelf has
no `--frames`, so FDE bounds come from `objdump --dwarf=frames`).
No execution of the node binary anywhere; no side effects beyond the packet
directory, the tool, and the test file.

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got` =
VA − 0x2000; `.rodata` = VA as-is. RELATIVE `.got` slots are zero-filled in
the file, so every GOT census below goes through `.rela.dyn` addends.

Validated boundaries (FDE, from `.eh_frame`): thunk `0x63ae260..0x63ae278`
(24B); sibling thunk `0x63ae280..0x63ae29a` (26B); worker
`0x63adf40..0x63ae252` (786B). Worker single `ret` at `0x63ae06a`; the
`__stack_chk_fail@plt` call at `0x63ae24d` is a noreturn path, not a second
return. Thunk single `ret` at `0x63ae277`.

Raw disassembly: the five excerpts beside this record (`thunk`, `head`,
`valid`, `kind`, `tail`; 222 bytes, 56 strict instructions, 2
byte-continuation lines excluded from strict counts). The full worker FDE was
read end to end; claims outside the excerpts are pinned by exact key bytes
(17 sites) and call targets (9 calls) in the verifier.

Callers/callees: thunk callers — chain FDE `0x63b1b60..0x63b1d5a` at
`0x63b1bad` (head, `r9d = 1` set at `0x63b1ba7`), `0x63b1c0a` (retry),
`0x63b1c75` (second-next). Thunk-B caller — FDE `0x63b46e0..0x63b4aeb` at
`0x63b479d`. Worker callers — the two thunks only (`0x63ae26e`, `0x63ae290`).
Worker callees — `0x63d9880` (thread == 0 detour, `0x63ae114`),
`0x63d9700` (miss handler, `0x63ae239`), `0x63adb50` (join, `0x63ae0c0`,
args thread, `[ref+0xe410]`, `rax`, literal `5`).
Indirect calls: none in the claimed bodies (0 LEA, 0 GOT for all three
targets; 60,723 `.rela.dyn` entries scanned, no addend hits; `.rela.plt` 278
entries contain no target either, by the same scan).

Source mapping evidence: none claimed — no source file or line is asserted
for these addresses. The `.data` byte `0x64ffc28` is the same address first
noted in packet #211; this worker reads it as the xor-gate switch
(`lea` at `0x63ae097`, `cmpb $0x0` at `0x63ae09e`).

Analysis completeness: the thunk body, the worker's key computation, table
lookup structure, overflow rotation, all gates, and the join tail were read
instruction by instruction. The two detour callees were read only to their
call sites and signatures; their bodies are not claimed.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is proposed in this
packet, so there is no independent path, Cargo graph, or two-build comparison
to report. The verifier is a byte-level static check, not a reimplementation.

## Results and limitations

Metrics with denominators: verifier exit 0 (5 excerpts, 222 bytes, 56 strict,
17 key-byte sites, 9 key calls, census 3/1/2 E8 sites, 0 E9/LEA/GOT, 60,723
`.rela.dyn` entries, 3 FDE bounds, MANIFEST 15/15 — see below for the suite
result). Unit tests 8/8 (verifier pass, exhibit bytes, strict counts with
per-line byte re-checks, census call targets, key-byte spot checks, tamper
control, MANIFEST coverage, records agreement).

What remains unknown, stated not inferred: (1) what `0x63d9700` does on a
full miss — insert, evict, or fail — and when it returns NULL; (2) what
`0x63d9880` initialises on the thread == 0 path and whether it can fail;
(3) the design intent of the overflow rotation (reported operationally only);
(4) what the entry word's low 16 bits encode that makes the sign-extended
masked value a dereferenceable pointer (the code dereferences it at
`0x63ae085`/`0x63ae0d0` regardless); (5) who writes the `[ref+0xec88]`-style
fields this family reads elsewhere (out of scope here).

Next question: decode the `0x63d9700` miss handler end to end — what it does
with `(thread, table, rbx, 0, 0)`, what entry pointer it returns, when it
returns NULL, and how it inserts or evicts on a full miss.
