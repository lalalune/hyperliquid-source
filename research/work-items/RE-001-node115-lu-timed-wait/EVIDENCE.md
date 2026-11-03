# RE-001-node115-lu-timed-wait: the inserter-side timed wait and wake-drain

- Component ID: `base/src/lu.rs` conversion context, FDE `0x5bb2440`
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit:
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only migration)
- Claim status: observation for all byte-level claims (body hash, call
  sites, syscall numbers, xorshift constants, census counts); inference
  for the behavior labels ("timed wait", "drain", "wake flag"); unresolved
  for the `+0x10 == 1` signal's writer, slot-word bit 3's meaning, the
  TLS check's semantics, the constructor's field values, the timeout
  handler's internals, and the foreign-node drain edge.
- Scope included and excluded: included is the full `0x5bb2440` body
  (4525 bytes, single ret at `0x5bb3486`) and its GOT/E8 census.
  Excluded (context only, referenced by address): the lookup, park,
  cleanup, contention-helper, table-creation, timeout-handler, TLS-check,
  vector-grow, constructor, and deadline-add bodies, and all callers
  beyond their census count.

## Reproduce

Working directory: the repository worktree at upstream main `8fd8db6`.
No execution of the node binary anywhere in this packet; all checks read
bytes only.

```
sha256sum artifacts/node/115/hl-node
# a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
objdump -d -M intel --start-address=0x5bb2440 --stop-address=0x5bb35ed \
  artifacts/node/115/hl-node > research/work-items/RE-001-node115-lu-timed-wait/fde2440.objdump.txt
readelf --debug-dump=frames artifacts/node/115/hl-node | grep 5bb2440
# FDE pc=0000000005bb2440..0000000005bb35ed
python3 tools/node115_lu_timed_wait.py
python3 -m unittest tests.test_node115_lu_timed_wait
make doctor   # analysis_ready true
make verify
make catalogue-check
make test     # 77 files; only failure is the pre-existing
              # test_node115_catalogue Errno 18 cross-device-link error
```

Tool versions: system `objdump`/`readelf` (binutils), python3 stdlib only
for the verifier and tests.

## Evidence

Coordinates are ELF virtual addresses (PIE); `.text` file offset =
VA − 0x1000, `.data.rel.ro`/`.got` file offset = VA − 0x2000,
`.rodata` file offset = VA. Body bytes are pinned in `fde2440.hex`
(SHA-256 `4f25e4444597bae4621a1bbb55307355749ce1e2e970efdb90f4e47ed0de9f19`).

Entry and hashing: `rdi` slot pointer saved to `[rsp+0x8]`,
`rdi * 0x9e3779b97f4a7c15` saved to `[rsp+0x30]`; `rsi` deadline
seconds to `[rsp+0x38]`, `edx` deadline nanoseconds to `[rsp+0x14]`,
`[rsp+0x7] = (edx != 0x3b9aca00)`. Second phase hashes `slot | 1`
(`or rdi,0x1` at `0x5bb2a1e`, `imul rbx,rdi` at `0x5bb2a27`).

Spin loops: first at `0x5bb24a8` (counter `ecx`, bound `0xa`;
`or 0x8` cmpxchg at `0x5bb2747`/`0x5bb2777`, `or 0x1` cmpxchg at
`0x5bb275d`/`0x5bb2795`, pause block at `0x5bb28ef`, yield call at
`0x5bb24d4`); second at `0x5bb2a70` (counter `[rsp+0x18]`, bound `9`;
`or 0x2` cmpxchg at `0x5bb2ad7`, pause block at `0x5bb2a83`, yield
call at `0x5bb2a50`, below-`0x10` return-1 at `0x5bb2f0d`).

TLS gate: `fs:[-0x4b0]` byte must be `1` (`0x5bb27b8`,
`0x5bb2afe`); TLS struct `fs:0 - 0x4d8` to `[rsp+0x20]`; check
`0x5bb5130` (206 bytes) called at `0x5bb24fb` and `0x5bb2ca0`.

Waiter nodes: first phase `[rsp+0x138]` (constructor GOT `0x64ec170`
→ `0x5bb6070` at `0x5bb2527`/`0x5bb2cc9`, 40-byte copy, flag
`[rsp+0x130]`, refcount GOT `0x64ec168` → `0x64fff20`); second phase
TLS node `[rsp+0x28]`; both with `+0x0` key, `+0x8 = 0`, `+0x18 = 8`,
`+0x20 = 1`, `+0x24` has-deadline byte. Bucket claim uses table
variable GOT `0x64ec148` → `0x64fff28`, helper GOT `0x64ec160` →
`0x5bb6790`, table creation GOT `0x64ec158` → `0x5bb6400`, cleanup
GOT `0x64ec150` → `0x5bb66b0`.

Futex waits: `syscall(202, word, 0x80, 1)` at `0x5bb25d5` (timed,
first phase), `0x5bb29b7` (untimed, via `r12` loaded from GOT
`0x64e06b8` at `0x5bb298c`), `0x5bb2c8a` (untimed, via `r12` loaded
at `0x5bb2c60`), `0x5bb2d75` (timed, second phase); wake
`syscall(202, entry+0x10, 0x81, 1)` at `0x5bb33f4`. Deadline sentinel:
nanos `== 0x3b9aca00` selects the NULL-timeout path in both phases
(`0x5bb2583`, `0x5bb2c51`); remaining time via `0x5c84210` at
`0x5bb2631`/`0x5bb2dd1`; clock via `0x5c842e0` at `0x5bb25eb`/
`0x5bb2d8b`/`0x5bb315a`; timeout handler `0x5bb3ca0` (417 bytes) at
`0x5bb264d`/`0x5bb2df2`.

State machine: first-phase exit `0x5bb29c1` tests `[node+0x10] == 1`
(`al = 1` → second phase `0x5bb2a0a`, `al = 0` → first-spin retry
`0x5bb24e0`); release → retry (`r15 = 1`); unlink → return `0`
(`r15 = 2` → `0x5bb3471`). Second-phase exit runs `lock xadd -10`
on the slot word at `0x5bb2f14` (reversing first-loop `+8` and
second-loop `+2`); old bit 0 clear → return `0`, set → drain with
claim value `1` (`ebx = 1` at `0x5bb2f2d`).

Drain: bucket claim on hash `[rsp+0x30]` at `0x5bb2f61`/`0x5bb2f83`;
list walk from `[bucket+0x8]` at `0x5bb2fe8`, key compare against
`[rsp+0x8]` at `0x5bb3043`, unlink at `0x5bb3079`, tail fixup at
`0x5bb3083`; vector push at `0x5bb30cd` (24-byte stride, inline base
`[rsp+0x68]` when count < 9, grow via `0x5bb5450` at `0x5bb30ff`
when count == 8); wake flag `[rsp+0x18]` set at `0x5bb3067` when
`(node+0x18 & 0xc) != 0` under accumulator bit 2; accumulator seed
`0x14` at `0x5bb3005`, add at `0x5bb3070`, dead after the walk;
bit-3 test at `0x5bb304a` unreachable (accumulator values `0x14`,
then `1`).

Deadline refresh: clock `0x5bb315a`, compare against
`[bucket+0x18]`/`[bucket+0x20]` at `0x5bb315f`/`0x5bb3168`; xorshift
on `[bucket+0x28]` at `0x5bb3175` (`<<13`, `>>17`, `<<5`), mod
`10^6` via `imul 0x431bde83`, `shr 50`, `imul 0xf4240`, subtract at
`0x5bb3192`/`0x5bb31a3`; deadline-add GOT `0x64ec178` → `0x5ca94e0`
(72 bytes: secs carry at `0x5ca94fa`, nanos wrap at `0x5ca94ff`,
signed-overflow panic at `0x5ca950b`) called at `0x5bb31ac`,
result to `[bucket+0x18]`/`[bucket+0x20]`.

Reset (unrolled by 4) at `0x5bb31f2`: `[node+0x10] = 0`,
`[node+0x20] = 0` dword, `[entry+0x8] = 1`,
`[entry+0x10] = node+0x20`. Slot bit-0 clear `lock and [slot], ~1`
at `0x5bb31d9`. Relocation `memcpy` GOT `0x64df508` at `0x5bb3355`
(176 bytes, `[rsp+0x78]` → `[rsp+0x140]`); wake loop at `0x5bb33d0`
entry, syscall at `0x5bb33f4`, flag-`2` skip at `0x5bb33d8`
(unreachable: flags are `0` at creation, `1` after reset); heap
free GOT `0x64df4a0` → `0x635de30` at `0x5bb346b`; single `ret`
at `0x5bb3486`.

Callers of `0x5bb2440`: 0 direct `E8`; 40 GOT-indirect sites via
slot `0x64e0ff0` (RELATIVE addend `0x5bb2440`), each inside a real
FDE (verified against the frame table). Analysis was complete over
the FDE body; no range was timed out or skipped.

## Implementation and comparison

Not yet implemented/measured: no independent Rust reimplementation is
included in this packet; the verifier pins bytes and census counts
only. Two-build comparison, normalized comparison, and fixture
identities are therefore not applicable. Corruption controls are in
the unit tests (body hex, ret placement, futex numbers, xorshift
shifts, division magic, records byte count).

## Results and limitations

Metrics with denominators: body 4525/4525 bytes pinned; 1/1 ret at
`0x5bb3486`; 10/10 cleanup, 3/3 table-create, 3/3 helper, 2/2
constructor, 1/1 deadline-add GOT sites; 5/5 futex sites (3 direct +
2 register-indirect); 40/40 caller GOT sites; 0 direct callers.
What passed: verifier exit 0, unit tests 7/7, `make doctor`
`analysis_ready` true, `make verify` 0, `make catalogue-check` 0.
What remains unknown: the `+0x10 == 1` writer, slot bit 3's meaning,
TLS check semantics, constructor fields, timeout-handler internals,
panic message texts, and the foreign-node drain edge. No gate is
requested. Next question: the vtable dispatch site that would settle
the wake-site `rdx` question (open since #188), or the timeout
handler `0x5bb3ca0` end to end.
