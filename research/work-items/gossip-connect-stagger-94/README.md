# node-runtime: node #94 gossip connect deadlines in `0x4740490` (wall-clock now + min(0.07 s, k·X/1000); snapshot durations unread)

Question: `0x4740490` (span name `update_and_get_overrides`) takes a locked
copy of a peer list and the timed override snapshot `0x45281c0`, then
schedules each candidate peer with a deadline. How is the deadline computed?
Does the function use the snapshot's two durations? The can1357 lead
(`update_and_get_overrides_and_connect_peers`, `node/connections.rs`) spawns
every connect at once. Where does it differ?

- Component ID: `node-runtime` (`docs/COMPONENTS.md`: CLI, startup, gossip,
  stream services; path rule `node/*`). The address is listed in
  `research/catalogue/seed-candidates.json` as a `node/connections.rs` seed.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for claims to test; no code, comments or names copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `node-runtime` research; no gate change.
- Scope: seven windows in `0x4740490` (entry, list and snapshot calls, delay
  factor, per-candidate deadline, register loads, index-overflow panic).
  Also the whole non-unwind body of the locked copy `0x45297f0`, the head of
  the wall clock `0x151cba0` and the head of the timestamp addition
  `0x1459ca0`. Two `[rsp+disp32]` censuses cover the whole `0x4740490` FDE.
  Excluded:
  - the candidate filtering before the deadline (`0x4740a52..0x4740cf0`,
    including the `[peer+0x30] < 100` test);
  - the bodies of the map search `0x42b8d90` and the scheduler `0x47bb530`;
  - what happens after scheduling;
  - release #115.
  The snapshot `0x45281c0` itself is bound by the separate packet
  `gossip-override-timing-94`.

## Reproduce

```sh
make verify
python3 tools/gossip_connect_stagger_static.py --json > research/work-items/gossip-connect-stagger-94/records.json
python3 -m unittest tests.test_gossip_connect_stagger_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries, and never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; under 1 s). `records.json` is
its complete output; the test suite regenerates it and compares.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has 10
windows (380 instructions), one for each checked byte window. All 17
`records.json` VAs that fall inside a window are instruction starts there.
The census entries are ModRM-byte addresses, not instruction starts. Each of
the 61 `FACTS` entries and the 22 decoded call, branch and RIP-relative
operands must lie inside a checked window, or the tool refuses.

## Evidence

### Inputs (observation)

- **Wall clock.** At entry, slot `0x576e8a0` (RELATIVE to `0x151cba0`) writes
  a timestamp to `[rsp+0xdc]`. `0x151cba0` calls the clock helper
  `0x4ee3800` with `edi = 0` (`CLOCK_REALTIME` on Linux).
- **Locked copy.** `0x45297f0` is called with base `[r14+0x10] + 0x10` and
  the name `clone` (`0x6fb46c`, length 5). It:
  - takes the lock byte `+0x2a0`;
  - copies the 5-byte entry list at `+0x2b0` (ptr) / `+0x2b8` (len);
  - reads a u64 **X** at `+0x2c0`, then unlocks;
  - returns `{.., ptr +0x8, len +0x10, X +0x18}`.
- **Snapshot.** `0x45281c0` writes `{tag, map words, wait, hold}` to
  `[rsp+0x180]`.

### Delay factor (observation)

| Snapshot | `[rsp+0x170]` | Other effect |
| --- | --- | --- |
| Some | X (as f64) × 0.001 (`0x20afb8`) | map root and height kept at `[rsp+0x158]`/`[rsp+0x160]` |
| None | 0.0 | `[rsp+0x18]` = 2^63 (`0x4740770`) |

Census of `[rsp+disp32]` with displacement `0x161..0x17f` over the whole FDE:
the two stores above, one read at `0x4740e40`, and an unrelated 8-byte store
to `[rsp+0x168]`.

### Per-candidate deadline (observation)

The candidate loop starts with `r14 = [rsp+0x18]` and `r12 = 2^63`
(`0x47408d3`/`0x47408d8`). Both are reloaded at `0x4740bed`/`0x4740bf2` and
`0x4740c1e`/`0x4740c23`. At `0x4740d06`, `cmp r14,r12`:

- **None** (equal): the deadline is the wall-clock `now` from `[rsp+0xdc]`.
- **Some**: the deadline is `now + min(0.07, k × [rsp+0x170])`. The cap is
  `0x20ac80` = 0.07 (`minsd`). The sum is formed by slot `0x576efb8`
  (RELATIVE to `0x1459ca0`), which multiplies the seconds by 1e9 first. `k`
  is chosen in this order:
  1. If the snapshot map root is non-null, `0x42b8d90` searches it with the
     peer's NodeIp (`peer+0x99`). If the result tag is not 1, `k` is the u64
     at `node + 8 + 8·idx`.
  2. Otherwise, `k` is the 0-based index of the first equal 5-byte entry in
     the locked list. The index has an overflow check that panics at
     `core/src/iter/adapters/enumerate.rs:120:17`.
  3. If the peer is not in the list, `k` is the list length (`[rsp+0x58]`).
- The deadline and an Arc are passed to `0x47bb530(peer+0x48, ..)`.

### Snapshot durations (observation)

The durations sit at `[rsp+0x1a0]` and `[rsp+0x1a8]`. The census of every
`[rsp+disp32]` with displacement `0x191..0x1af` over the whole FDE finds:

- the only operand at `0x1a0` or above: `0x47404fc`, which is before the
  snapshot call (it reads an earlier result);
- four 8-byte `mov` loads from `[rsp+0x198]`. These are checked as REX.W
  `8b`, so they do not reach `0x1a0`.

After `0x4740670`, nothing in `0x4740490` reads either duration directly.

## Lead comparison

| Point | Binary | Lead |
| --- | --- | --- |
| When connects start | per-peer deadline: wall-clock now + `min(0.07, k·X/1000)` s | `tokio::spawn` for each candidate at once |
| Stagger source | X (u64 at locked base `+0x2c0`) and `k` from the snapshot map or list position | none |
| Snapshot None | every deadline = now; connects still scheduled | returns an empty task list |
| Snapshot durations | not read after the call | not used for scheduling either; fields kept in the snapshot struct |
| Clock | `CLOCK_REALTIME` timestamp | `Instant::now()` |

Reading X as milliseconds, k = 0, 1, 2 … gives delays 0, X, 2X ms, up to
70 ms.

## Inference

- X behaves as a per-step stagger in milliseconds, because of the 0.001
  factor and the seconds-based addition. Its field name is not in the binary.
- `[rsp+0x18]` in the Some path is the copied list's capacity, which is never
  2^63, so `cmp r14,r12` separates None from Some. A full census of `r14` and
  `r12` writes inside the loop is not tool-checked; the windows cover the
  loads and reloads.
- Search tag 1 is the "not found" result, as with Rust's BTreeMap search.
- The next users of `[rsp+0x180]` after the call (the memcpy destination at
  `0x4740858` and the output pointer of `0x4878770`) treat it as output. So
  the durations are discarded, but whether `0x4878770` writes before it reads
  is not checked.

## Unresolved

- What `0x47bb530` does with the deadline and what result 5 means.
- The candidate filtering in `0x4740a52..0x4740cf0`.
- What the snapshot map values mean as `k`.
- Who writes X.

## Controls

- `tests/test_gossip_connect_stagger_static.py` checks:
  - the models `k_value` and `delay`, and the stagger shape;
  - the constants, the locked copy, the duration and factor censuses and the
    names;
  - regeneration of `records.json` and the CLI.
- Corruption tests (each must raise `EvidenceError`):
  - the 0.07 cap, the 0.001 factor and the 1e9 multiplier;
  - the None branch;
  - the wall clock id;
  - the addition and wall-clock RELATIVE slots;
  - a planted duration read and a planted factor read;
  - the name string;
  - the enumerate Location.
- Both toolchains: the module passes with GNU binutils on `PATH` and with only
  LLVM; the tool itself uses neither.
