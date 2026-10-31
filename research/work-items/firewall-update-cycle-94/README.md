# node-runtime: node #94 firewall IP update cycle in `0x28f6960` (skip flag, wall-clock throttle on `firewall_ips_maybe_update`, store only when changed, no mismatch log)

Question: `0x28f6960` runs the sections `firewall_ips_maybe_update`,
`check_computed_ips` and `update_computed_ips`. Which of them run on a given
call, what decides whether the computed IPs are stored, and what happens when
a section is slow? The can1357 lead (`node/firewall_ips.rs`,
`firewall_ips_maybe_update`) returns early for non-validators, logs a
firewall mismatch and stops, and otherwise stores the computed set when it
differs from the cache. Where does the binary differ?

- Component ID: `node-runtime` (`docs/COMPONENTS.md`: CLI, startup, gossip,
  stream services; path rule `node/*`). The address is listed in
  `research/catalogue/seed-candidates.json` as a `node/firewall_ips.rs` seed.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for claims to test; no code, comments or names copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `node-runtime` research; no gate change.
- Scope: `0x28f6960` from entry to the loader call (`0x28f6960..0x28f6d80`)
  and its slow-path blocks (`0x28f714a..0x28f72a4`). Also:
  - the lock and sleep parts of the `firewall_ips_maybe_update` section
    `0x27dc3f0`;
  - the whole non-unwind body of the `check_computed_ips` section
    `0x27cdf00`;
  - the lock at the head of the `update_computed_ips` section `0x27d6460`;
  - the length tests and results of the equality helpers `0x28a6f50` (set)
    and `0x28a73c0` (map);
  - the lazy initialiser `0x143ea60`.

  A byte scan of the whole `0x28f6960` FDE looks for log calls. Excluded:
  - the closures `0x222d750` (maybe_update) and the bodies of `0x45c3d20`
    (abci builder) and `0x45c42b0` (compute);
  - everything after the loader call `0x28f52d0`: the two high-water updates
    of `[rbp+0x2d0]`/`[rbp+0x2d8]`, the `update` section `0x27cf3a0`, the
    publish through `[rbp+0x2a0]` and the final timing call (`execution_state.rs:185:30`);
  - the twin layout `0x4548cc0`;
  - release #115.

## Reproduce

```sh
make verify
python3 tools/firewall_update_cycle_static.py --json > research/work-items/firewall-update-cycle-94/records.json
python3 -m unittest tests.test_firewall_update_cycle_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries, and never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; under 1 s). `records.json` is
its complete output; the test suite regenerates it and compares.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has
12 windows (506 instructions), one for each checked byte window. All 23
`records.json` VAs that fall inside a window are instruction starts there.
Each of the 92 `FACTS` entries and the 50 decoded call, branch and
RIP-relative operands must lie inside a checked window, or the tool refuses.
Eight RELATIVE slots are resolved and checked.

## Evidence

`rbp` = `rdi` (the poller) and `r15` = `rsi` (the state). Each section is a
timed lock in the same shape as `0x45281c0` (packet
`gossip-override-timing-94`, PR #517): it returns `{wait, hold}` in seconds, and
calls `0x13c9e20(50)` before returning when its flag argument is set.

### Control flow (observation)

```text
if byte [rbp+0x260] == 1:                      ; 0x28f698a
    loader_flag = 0; goto loader               ; 0x28f6993, 0x28f6998
ran = 0
if dword [rbp+0x280] == 0 or elapsed(now, [rbp+0x280]) > f64 [rbp+0x278]:
    [rbp+0x280] = now                          ; wall clock 0x151cba0, elapsed 0x1447130
    firewall_ips_maybe_update(lock [rbp+0x298]+0x10, sleep flag [[rbp+0x298]+0x5e0])
    ran = 1
    slow_check(wait + hold)
abci = 0x45c3d20(byte [r15+0x8f2], r15+0x8f8, {1, 20 bytes [rbp+0x261]})
computed = 0x45c42b0(abci, byte [r15+0x8f2], [rbp+0x298]+0x10, ran)
changed = check_computed_ips(lock [rbp+0x290]+0x10, &computed, sleep flag [[rbp+0x290]+0x5c8])
slow_check(wait + hold)
if changed:
    update_computed_ips(lock [rbp+0x290]+0x10, computed, same flag); slow_check(wait + hold)
else:
    drop computed
loader_flag = 1
loader: 0x28f52d0([rsp+0x318], r15, {1, [rbp+0x2d0], [rbp+0x2d8]}, &loader_flag)
```

### Sections (observation)

| Section | Lock on `base + 0x568` | Body |
| --- | --- | --- |
| `firewall_ips_maybe_update` (`0x27dc3f0`, base `[rbp+0x298]+0x10`) | write (`cmpxchg 0 -> 8`) | `0x222d750(base+0x570)` |
| `check_computed_ips` (`0x27cdf00`, base `[rbp+0x290]+0x10`) | read (`+0x10`; `lock xadd -0x10` to release) | three equality tests |
| `update_computed_ips` (`0x27d6460`, base `[rbp+0x290]+0x10`) | write (`cmpxchg 0 -> 8`) | not decoded |

`check_computed_ips` sets
`changed = not (map_eq(base+0x570, v) and set_eq(base+0x588, v+0x18) and set_eq(base+0x5a0, v+0x30))`.
The tests short-circuit: the first false one leaves `changed = 1`. Both
equality helpers return false when the `+0x10` lengths differ. The map helper
returns true when both maps are empty. `changed` is returned at `+0x10` of the
section result, and `update_computed_ips` runs only when it is non-zero.

### Slow sections (observation)

After each section, `wait + hold` is compared with `0x20aab8` = 3.0. If it
is greater, and the byte at `0x577b288 + 0x48` (≤ 0x1f) has its bit set in
`0x803c6000`, the code calls `call_once` (slot `0x576e8b8`, Location
`std/src/sync/once.rs:219:20`) on the lazy static `0x577ab80`, but only while
its state `0x577ab98` is not 0. The init `0x143ea60` takes the stored init
function, calls it and writes 24 bytes. Nothing else happens on this path.

The whole FDE `0x28f6960..0x28f7302` has no `e8` call to the log emitter
`0x143d010` or to the mismatch logger `0x4b28ff0`, and no `ff15` call through
slot `0x576e978`.

## Lead comparison

| Point | Binary | Lead |
| --- | --- | --- |
| Early exit | byte `[rbp+0x260] == 1` skips all three sections, and the loader still runs with flag 0 | `!is_validator` returns `NotAValidator` |
| `firewall_ips_maybe_update` | runs at most once per `[rbp+0x278]` seconds (wall clock); whether it ran is passed to the compute step | no throttle |
| Mismatch | no mismatch log in this function | logs and returns `Mismatch` before any update |
| Store decision | `check_computed_ips` compares three fields (one map, two sets) under a read lock | compares one computed set with the cache |
| Store | `update_computed_ips` under the write lock of the same RwLock | plain assignment |
| Slow sections | > 3.0 s only forces a lazy static | not modelled |

## Inference

- `[rbp+0x260]` with the 20-byte payload at `+0x261` looks like an
  `Option`-like value whose tag 1 means "skip". Its meaning (for example
  "not a validator") is not checked.
- The 3.0 s branch looks like a tracing slow-section event whose emission was
  compiled out, leaving only the lazy callsite initialisation. The lazy
  static's type is not decoded.
- The two timed-lock bases at `[rbp+0x298]` and `[rbp+0x290]` are separate
  shared objects: firewall state and computed-IP state.

## Unresolved

- What `0x222d750`, `0x45c3d20` and `0x45c42b0` compute, and how the `ran`
  flag changes the result.
- What `update_computed_ips` writes.
- The interval value and who sets `[rbp+0x260]`.
- The steps after the loader call.

## Controls

- `tests/test_firewall_update_cycle_static.py` checks:
  - the models `changed` and `cycle`, including "check runs while throttled";
  - the section names, the slow threshold and Location, the log scan and
    the lock kinds;
  - regeneration of `records.json` and the CLI.
- Corruption tests (each must raise `EvidenceError`):
  - the 3.0 constant;
  - the skip value, the update gate, the `xor bpl,1` and a map length offset;
  - a section name and the lazy Location;
  - the compute and lazy-vtable RELATIVE slots;
  - a planted `e8` call to the log emitter.
- Both toolchains: the module passes with GNU binutils on `PATH` and with only
  LLVM; the tool itself uses neither.
