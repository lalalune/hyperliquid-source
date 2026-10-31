# node-runtime: node #94 timed gossip-override snapshot `0x45281c0` (lock wait and lock hold, not update and clone)

Question: `0x45281c0` returns an optional override map and two f64 durations.
What do the two durations measure? When is the map included? The can1357 lead
(`update_and_get_overrides_with_file_tracker`, `node/connections.rs`) calls
them `update_elapsed_secs` and `clone_elapsed_secs`. Where does it differ?

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
- Scope: the whole non-unwind body of `0x45281c0` (`0x45281c0..0x4528490`),
  the call site in `0x4740490` (`0x4740549..0x4740675`), and the two clock
  helpers `0x4ee3800` and `0x4ee3730`. Excluded: the bodies of the tracker
  refresh `0x471edd0`, the map clone `0x498e1f0`, the locked copy
  `0x45297f0`, the target of the 50-argument call, and release #115.

## Reproduce

```sh
make verify
python3 tools/gossip_override_timing_static.py --json > research/work-items/gossip-override-timing-94/records.json
python3 -m unittest tests.test_gossip_override_timing_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` and `R_X86_64_GLOB_DAT` entries (the latter named through
`.dynsym`/`.dynstr`), and never executes the target. It needs only Python 3
(run here with 3.14.7 on macOS arm64; under 1 s). `records.json` is its
complete output; the test suite regenerates it and compares.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has 4
windows (298 instructions), one for each checked byte window. All 14
`records.json` VAs that fall inside a window are instruction starts there.
Each of the 71 `FACTS` entries and the 26 decoded call, branch and
RIP-relative operands must lie inside a checked window, or the tool refuses.

## Evidence

### Clock (observation)

- `0x4ee3800` calls the `clock_gettime` GLOB_DAT slot `0x576ea88` with the
  clock id in `edi`. It checks that nanos are below `1e9` and returns
  `(secs, nanos)`.
- All three reads in `0x45281c0` pass `edi = 1` (`CLOCK_MONOTONIC` on Linux).
- `0x4ee3730(out, lhs, rhs)` stores tag 0 and `lhs - rhs` when `lhs >= rhs`,
  and tag 1 otherwise.
- Each caller site turns tag 0 into `secs + nanos / 1e9` (divisor
  `0x20a220` = 1e9.0) and any other tag into 0.0.

### The two durations (observation)

`rdx` (kept in `r12`) is the base pointer.

| Step | VA | Effect |
| --- | --- | --- |
| `t0` | `0x45281e3` | read before the lock |
| lock | `0x45281ff` | `lock cmpxchg` 0 → 1 on byte `base+0x2a0` (slow path `0x452845f`) |
| `t1` | `0x4528214` | read after the lock is held |
| first | `0x4528243` | `t1 - t0` (`[rsp+0x60] - [rsp+0x40]`), stored at `[rsp+0x70]` |
| refresh | `0x452829e` | `0x471edd0(base+0x2a8, Location connections.rs:163:45)` |
| clone | `0x4528346` | see below |
| unlock | `0x4528373` | `lock cmpxchg` 1 → 0 on the same byte |
| `t2` | `0x4528382` | read after the unlock |
| second | `0x45283ab` | `t2 - t1` (`[rsp+0x78] - [rsp+0x60]`) |

The 0x30-byte result is: `+0x0` Option tag, `+0x8..+0x20` the three map
words, `+0x20` the first duration and `+0x28` the second.

So the first duration covers only the wait for the lock byte. The second
covers everything done while holding it (tracker refresh, include test, map
clone) and the release.

### What is included (observation)

- After the refresh, when `[base+0x2f8] != 0`, it logs
  `Last load of FileModTimeTracker failed: {}` (template `0x1f3bf3`) at
  `base/src/file_mod_time_tracker.rs:63:13`.
- The map is included when byte `[base+0x2d8]` is nonzero or bit 0 of the
  caller's flag byte (`[rcx]`, read at entry) is set. Otherwise the tag is 0.
- When included, the tag is 1 and the payload is built from the map at
  `base+0x2c0` (root), `+0x2c8` (height) and `+0x2d0` (length):
  - length 0: an empty map;
  - root non-null: a clone through `0x498e1f0`;
  - root null with nonzero length: an unwrap panic at
    `library/alloc/src/collections/btree/map.rs:306:46`.
- When the first stack argument byte (`[rsp+0xc0]`: six pushes, a 0x88 frame
  and the return address) is nonzero, the function calls RELATIVE slot
  `0x576e8f8` (`0x13c9e20`) with `edi = 50` and discards the result.

### The only caller (observation)

`0x45281c0` has no RELATIVE slot. Its one direct call is `0x4740670` in
`0x4740490`:

- base = `[r14+0x18] + 0x10`;
- the flag byte is at `[rsp+0x30]`;
- the stack argument is 1, so the 50-argument call always runs on this path;
- `r8`/`r9` carry `update_and_get_overrides` (`0x6fb471`, length 0x18).

The flag is set when the node's own `Option<NodeIp>` at `[r14+0x20]` (tag 2 =
None) is Some and appears in the list returned just before by `0x45297f0`
(called with `clone`, `0x6fb46c`, length 5).

## Lead comparison

| Point | Binary | Lead |
| --- | --- | --- |
| First duration | wait for the lock byte (`t1 - t0`) | `update_elapsed_secs`: time in `load_if_modified` |
| Second duration | lock held: refresh, include test, clone and unlock (`t2 - t1`) | `clone_elapsed_secs`: time to clone `last_value` |
| Clock | `CLOCK_MONOTONIC`, a negative interval gives 0.0 | `Instant::elapsed` |
| Include test | `[base+0x2d8]` or the caller's flag | `force_include_current` parameter or non-empty value |
| Force flag source | own NodeIp is in the locked list | caller argument |
| Payload | 3-word BTreeMap, no timestamp | `GossipConfigInner` plus `loaded_at: SystemTime` |
| Extra call | `0x13c9e20(50)` with a stack flag (always 1 here) | none |

With an uncontended lock, the binary's first value is about 0 and its second is
about the lead's two values added together. Under contention, the first value
grows while the lead's values do not change.

## Inference

- The shape (time to acquire, time held, a name and length in `r8`/`r9`, and
  a flag that triggers a 50-argument call) reads like an inlined timed-lock
  helper. `0x45297f0` follows the same pattern on the same lock byte
  `+0x2a0`. That function is not checked here.
- `[base+0x2d8]` plays the role of the lead's "value present" test. Its field
  name is not in the binary.
- `0x45281c0` does not read `r8` or `r9`; this is seen in the excerpt and not
  checked by the tool.

## Unresolved

- What `0x13c9e20(50)` does. It reads a thread-local 64-entry buffer, and its
  result is discarded.
- What `0x471edd0` refreshes and which field `[base+0x2f8]` is.
- What the map's keys and values are.
- What `0x4740490` does with the two durations.

## Controls

- `tests/test_gossip_override_timing_static.py` checks:
  - the models `seconds`, `binary_durations`, `lead_durations` and `snapshot`;
  - the clock, timing, body and caller results;
  - regeneration of `records.json` and the CLI.
- Corruption tests (each must raise `EvidenceError`):
  - the clock id;
  - swapping the two subtraction operands;
  - the 1e9 divisor;
  - the `clock_gettime` GLOB_DAT slot;
  - the tracker-error Location line;
  - the tracker template;
  - the `update_and_get_overrides` name;
  - the 50-call RELATIVE slot;
  - a new RELATIVE slot pointing at the function;
  - a fact outside every window.
- Both toolchains: the module passes with GNU binutils on `PATH` and with only
  LLVM; the tool itself uses neither.
