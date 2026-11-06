# RE-001-node115-lu-gate: the node #115 lu gate

- Component ID: RE-001-node115-lu-gate
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30`
  (confirmed before analysis)
- Claim status: observation for all byte-level claims; inference for
  the (cursor, remaining) reading of `+0xe0`/`+0xe8` and the
  exhaustion-marker reading of the drain path; unresolved for the
  identities of `0x63c2130`, `0x63c2450`, and `0x63ba600`
- Scope included and excluded: the gate FDE `0x63b85f0..0x63b8820`
  only. The driver FDE, the single-shot caller FDE, the allocator,
  the resolver, the release helper, and the consume helper are
  cited by address only, not claimed here.

## Reproduce

Static analysis only; the binary was never executed. In the
worktree root:

- `objdump -d --start-address=0x63b85f0 --stop-address=0x63b8820
  artifacts/node/115/hl-node` reproduces the full FDE text
  (exhibits are contiguous slices of it).
- `readelf --debug-dump=frames artifacts/node/115/hl-node`
  confirms `pc=0x63b85f0..0x63b8820`.
- `python3 tools/node115_lu_gate.py` runs the static verifier
  (byte reads only).
- `python3 -m unittest tests.test_node115_lu_gate` runs the
  packet unit tests (10 tests: regeneration comparison plus
  tamper controls; objdump header lines are stripped before
  comparison because objdump embeds the invoked path).
- Coordinate system: `.text` file offset = VA - `0x1000`.

## Evidence

- Entry `endbr64`, pushes, `r14 = rsi+0x70`, `r13 = rsi+0xb0`,
  `r12 = rcx`, `rbp = rdi`, `rbx = rsi`. Lock:
  `pthread_mutex_trylock(rsi+0xb0)`; failure path calls
  `0x63bf680(rsi+0x70)`, stores `1` to `[rsi+0xd8]`, retries.
- Accounting: `[rsi+0xa8]++`; if `[rsi+0xa0] != rdi` then
  `[rsi+0x98]++` and `[rsi+0xa0] := rdi`.
- Flag byte: `*(r12) := 0` at `0x63b865c`, after lock and
  accounting; `*(r12) := 1` at `0x63b8800`, the fail path.
  `r12` is never reassigned in the FDE (only these two stores
  through it exist).
- Size argument: the incoming `rdx` is never read. The main
  path overwrites `edx` with `0xf8` before the allocator call;
  the setup path overwrites `edx` with `0x200000` before the
  resolver call.
- Arena test: `cmpq $0x0, 0xe0(%rbx)`; zero diverts to the
  setup path at `0x63b8728`.
- Main path: `rsi = [rbx+0xf0]`, `ecx = 0x40`, `edx = 0xf8`,
  `rdi = rbp`; `cmpq $0x200000, 0xe8(%rbx)`; equal diverts to
  the drain path at `0x63b8790`. Allocator call `0x636b370`
  at `0x63b868c`; NULL result diverts to the fail path at
  `0x63b8800`.
- Consume: `r14 = [rbx+0xe0]`, `rdx = [rbx+0xf8]`, call
  `0x63ba600` at `0x63b86bc`; `[rbx+0xf8] := rdx + 1`;
  `[rbx+0xe0] += 0x200000`; `[rbx+0xe8] -= 0x200000`;
  `[rbx+0xd8] := 0`; unlock; return the allocator result in
  `rbp`.
- Setup path: stack byte `:= 1`; call `0x63c2130(0,
  0x10000000, 0x200000, &stack-byte)` at `0x63b873e`; NULL
  result diverts to the fail path. Otherwise allocator call
  at `0x63b8763`; NULL result calls `0x63c2450(result,
  0x10000000)` at `0x63b87f8`, then diverts to the fail path.
  On success `[rbx+0xe0] := resolver-result`,
  `[rbx+0xe8] := 0x10000000`, and control jumps to the consume
  call at `0x63b86a4`.
- Drain path: allocator call at `0x63b8790`; NULL result
  diverts to the fail path. Otherwise consume call at
  `0x63b87b9`; then `[rbx+0xe0] := 0`, `[rbx+0xe8] := 0`,
  `[rbx+0xd8] := 0`, unlock, return the allocator result.
- Fail path: `*(r12) := 1`, `rbp := 0`, `[rbx+0xd8] := 0`,
  unlock, jump to the shared epilogue (canary check, pops,
  `rax := rbp`, single `ret` at `0x63b8709`).
- Driver use (cited only): gate call site `0x63b8ec2` with
  `(rbp, [r14+0x38], r12, stack-slot value)`; `test %rax,%rax`
  then `je 0x63b8f70` (epilogue, round 3 skipped). On nonzero
  return the driver calls `0x63d94b0(r14+0x140, gate-return)`
  before round 3.
- Single-shot caller use (cited only): gate call site
  `0x63b8bdc` with `(r12, [rbx+0x38], r13, (%rsp))`;
  NULL-tested to its epilogue.
- Census method: whole-`.text` byte scan for `E8`/`E9` rel32
  targets and rip-relative `LEA` displacements, plus
  `.rela.dyn` addend scan (60,723 entries). Direct `E8`:
  `0x63b8bdc`, `0x63b8ec2`. Direct `E9`: none. `LEA`: none.
  GOT: none. Internal direct branch targets: all inside the
  FDE. Internal call sites: 13 (trylock, contention,
  allocator x3, consume x2, resolver, release, unlock x3,
  stack-check).
- Disjointness method: every `records.json` exhibit range in
  the worktree was compared against `0x63b85f0..0x63b8820`;
  no overlap. No record mentions `0x63b85f0`.

## Implementation and comparison

Not yet implemented/measured: this packet is evidence only, no
Rust reconstruction is claimed. No execution of the node binary
at any point.

## Results and limitations

- Verifier: exit 0 (6 excerpts, 389 bytes, 78 strict
  mnemonics, census 2 E8 sites, MANIFEST 17/17).
- Unit tests: 10/10.
- `make verify`: exit 0 (559 manifests, 7171 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md`, identically on a pristine
  `05bc2de30` checkout — pre-existing upstream staleness,
  not a packet regression.
- Full `make test`: not attempted on the new base (584 files).
- Unknowns carried forward: the identities of `0x63c2130`,
  `0x63c2450`, and `0x63ba600`; whether `+0xe0` is an address
  cursor or a byte count; the meaning of `+0xf8` and `+0xd8`;
  who reads the flag byte; why the size argument is ignored.
- Next question: decode the consume helper `0x63ba600` end
  to end: what it does with the allocator block and the cursor
  value, and how that explains the gate's `+0xe0`/`+0xe8`
  bookkeeping.
