# node-runtime: node #94 `gossip rpc height` retry loop (tries field unused, bound u64::MAX, constant 2.0 s)

Question: the startup future `0x22689f0` wraps its peer height query in an
`AsyncSleepRetry` record {peer list, `gossip rpc height`, 10, 2.0}. Does the
loop stop after 10 attempts? What does it sleep between attempts? What does
the `n_tries=` field of its failure log print? Where does the can1357 lead
(`net_utils/async_sleep_retry.rs`) differ?

- Component ID: `node-runtime` (`docs/COMPONENTS.md`: CLI, startup, gossip,
  stream services; path rule `node/*`).
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for seed addresses and claims to test; no code, comments or names
  copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `node-runtime` research; no gate change.
- Scope: seven fixed windows in `0x22689f0`, the whole formatter FDE
  `0x1570900`, and a census of fifteen `[rbx+disp32]` retry-state fields over
  the whole `0x22689f0` FDE. It also covers the bound, the count store and
  every record-pointer load in all eight FDEs that build a
  `{descriptor, 10, 2.0}` record (the census of open PR #211). Excluded: the
  body of each attempt, the sleep futures, and release #115.

## Reproduce

```sh
make verify
python3 tools/height_retry_static.py --json > research/work-items/height-retry-94/records.json
python3 -m unittest tests.test_height_retry_static -v
```

The producer authenticates the input against `provenance/artifacts.json`, parses
sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries, and never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; under 1 s). `records.json` is
its complete output; the test suite regenerates and compares it.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47, in 52
windows (371 instructions), one per checked byte window (the `0x22689f0`
pointer loads appear twice). All 56 `records.json` VAs that fall inside a
window are instruction starts there. The `census` entries are ModRM-byte
addresses, not instruction starts.

Format templates are decoded as rustc 1.94 packs them: a byte below 0x80 is a
literal length, and `0xc0` is a placeholder followed by the length of the next
literal; `0x00` ends the template. Reading placeholder *k* as format
argument *k* is an inference.

## Evidence

### The record (observation)

Window `0x2268b78..0x2268bd7` builds the record at `[rbx+0x3b98]`. The fields are:

| Offset | Value |
| --- | --- |
| `+0x0` | `&[rbx+0x3b90]`, which holds `[rbx+0x3b88]` |
| `+0x8`, `+0x10` | `gossip rpc height` (`0x3d7953`), length 17 |
| `+0x18` | 10 |
| `+0x20` | f64 2.0 |

The record's address goes to `[rbx+0x3bc0]`. The init window copies it to
`[rbx+0x3c60]` and `[rbx+0x3c30]`.

### The attempt bound is `max(u64::MAX, 1)` (observation)

- **Raw tries:** window `0x2268c15..0x2268c9d` loads `rax = -1`
  (`0x2268c53`) and stores it to `[rbx+0x3c38]`. It also stores -1 to
  `[rbx+0x3c28]` (`0x2268c1c`), the value the resume path `0x2268d08`
  reloads into `rax` before jumping back to `0x2268c5a`.
- **Bound:** `cmp rax,1; adc rax,0` gives `max(rax, 1)`, stored to
  `[rbx+0x3bd0]`. That is `u64::MAX`.
- **Counter:** `[rbx+0x3bc8]` starts at 0, and the first attempt is entered
  with `rcx = 0` (`0x2268c97 → 0x2269c51`).
- **Each later attempt:** window `0x2269c3a..0x2269c6d` compares the counter
  with the bound. `jae` goes to `0x2268c9d` (exhausted). Otherwise it stores
  `counter + 1` and copies the old counter to `[rbx+0x3c58]`.

### The record's 10 is never read in `0x22689f0` (observation)

A ModRM byte scan of the whole FDE for `[rbx+disp32]` operands finds exactly
the sites in `records.json` `census`. Highlights:

- **The 10:** `[rbx+0x3bb0]` (record `+0x18`) has one operand, its store.
- **The record pointer:** `[rbx+0x3c30]` has four operands: the store and
  three loads. Each load is followed by a use at offset `+0x0` (the peer
  list chain, `0x2269c63`), `+0x8` (the descriptor, `0x226a79b`) or `+0x20`
  (the 2.0 sleep, `0x226a895`).
- **The other copies:** `[rbx+0x3bc0]` and `[rbx+0x3c60]` are each read once.
  The value goes back into `rcx` and from there to `[rbx+0x3c30]`.
- **The bound:** `[rbx+0x3bd0]` has its single store and the one compare
  read.

No operand in this FDE reads offset `+0x18` through these pointers. A callee
reading the record through a pointer passed in a register is not excluded,
but the only pointer derived from these loads that reaches a call is
`record + 8`, as the descriptor argument of the failure log.

### Failure log and sleep (observation)

Window `0x226a753..0x226a8bc` (reached when an attempt fails) builds three
format arguments:

1. `[rbx+0x3c30] + 8`, the descriptor.
2. `&[rbx+0x3c58]`, the attempt index, with the formatter from RELATIVE slot
   `0x576e090` (`0x1570900`).
3. `&[rbx+0x3c88]`, the error.

The template `0x1f2256` reads
`AsyncSleepRetry::retry desc=[{}] n_tries={} failed: {}`. `0x1570900` loads
`[rdi]`, renders it into a 20-byte buffer (`0x1570470`), and calls a
pad-integral-shaped slot with `is_nonnegative = 1`, so it prints the plain
`u64` value.

The window then loads `[[rbx+0x3c30]+0x20]` (2.0) into `xmm0` and jumps to
`0x2269bcc`. That window stores it to `[rbx+0x3ce0]`. It skips the sleep only
if the value is exactly 0.0; otherwise it polls `0x2269bfe → 0x2237090`
(pending: `0x226a8d6`) and then starts the next attempt.

### Exhaustion log (observation)

Window `0x2268dd7..0x2268e57` formats
`async_sleep_retry retries exhausted: {} @@ [n_retries: {}]` (template
`0x1ebd40`). Argument 1 is `&&[rbx+0x3c38]` (the raw -1) through `[rsp+0x20]`,
with formatter `0x26aaba0` (not decoded here).

### Inference

The `gossip rpc height` step retries until it succeeds (up to 2^64 − 1
attempts). It sleeps a constant 2.0 s after every failure and logs a
0-based attempt index as `n_tries`. The record's 10 is carried but unused
here. The peer list behind `+0x0` is the one the peer height loop iterates
(see the open local-abci packet,
[#430](https://github.com/lalalune/hyperliquid-source/pull/430)).

### All eight `{descriptor, 10, 2.0}` records (observation)

PR #211's byte census found exactly eight `mov [rbx+d],10; movabs rax,2.0`
sites. The table names each FDE's descriptor. In every one of those FDEs:

1. **Bound:** the retry init loads `rax = -1` and computes
   `cmp rax,1; adc rax,0`, then stores the result as the bound and enters the
   first attempt with `rcx = 0 < bound` (`jb`). The window from `mov rax,-1`
   to that `jb` is pinned per site.
2. **Pointer loads:** each load of the record-pointer slot is pinned up to the
   instruction that overwrites the register or leaves the block. None of these
   spans has a `[reg+0x18]` operand. The uses are `+0x0`, `+0x8` (by `add`)
   and `+0x20` at every site.
3. **Extra loads at two sites:** in `0x438ed70` and `0x47b4950`, two further
   loads read `+0x10` into a `lock cmpxchg` loop, or jump to a block that
   stores the slot elsewhere.

| FDE | Descriptor | Count store | Bound window | Pointer slot |
| --- | --- | --- | --- | --- |
| `0x22c54a0` | `NodePort::listen` | `0x22c55c2` | `0x22c5620` | `[rbx+0x40]` (disp8, not censused) |
| `0x438ed70` | `NodePort::listen` | `0x438f2c1` | `0x438f328` | `[rbx+0x278]` |
| `0x47b4950` | `NodePort::listen` | `0x47b4b79` | `0x47b4bdf` | `[rbx+0x298]` |
| `0x2039060` | `rpc connect …` | `0x20392ba` | `0x2039321` | `[rbx+0x1a8]` |
| `0x4387f40` | `rpc connect …` | `0x438819a` | `0x4388201` | `[rbx+0x1a8]` |
| `0x439fa90` | `tcp_stream_with_retry …` | `0x439fb54` | `0x439fbf5` | `[rbx+0xc0]` |
| `0x4b399a0` | `tcp_stream_with_retry …` | `0x4b39c79` | `0x4b39cf0` | `[rbx+0x280]` |
| `0x22689f0` | `gossip rpc height` | `0x2268bb4` | `0x2268c53` | `[rbx+0x3c30]` |

Censuses of the pointer, bound and count slots (disp32 slots only) are pinned
in `records.json` `sites`:

- **Count slot:** has its one store at five sites. At the two `rpc connect`
  sites `[rbx+0x160]` also takes a 60.0, a register store and two LEAs. At
  the two `tcp_stream_with_retry` sites the 10 is overwritten with -1 when
  `bpl` is 0 (`0x439fb75`, `0x4b39c9a`). No count-slot operand is a load.
- **NodePort extras:** the NodePort FDEs `0x438ed70` and `0x47b4950` also
  store to the pointer and bound slots in another state (for example
  `0x438fb04`, `0x438fc47`). Inference: that is storage reuse by a later
  future state. This is not resolved here.

Inference: every `{descriptor, 10, 2.0}` retry in node #94 is bounded only by
`u64::MAX` attempts and sleeps its record's 2.0 s between them. The 10 (or
the -1 written over it) is not consulted by any of these loops.

## Comparison with the lead

- **Bound:** `async_sleep_retry` uses `max_tries = policy.max_tries.max(1)`
  and `for attempt in 0..max_tries`. The binary has the same
  `max(.., 1)` shape, but its input is the constant -1, not the record's 10.
  So the height step is not bounded by 10 tries.
- **Logged count:** the lead passes `attempt + 1` to `log_retry_failure`. The
  binary logs the 0-based index (the counter before its increment).
- **Last sleep:** the lead skips the sleep after the last attempt
  (`attempt + 1 != max_tries`). The binary has no such check on this path,
  only the zero-delay skip, which is moot with a bound of `u64::MAX`.
- **Delay:** the lead's delay comes from a caller closure. Here it is the
  record's 2.0 every time, with no growth.
- **Other instances:** `AsyncSleepRetryPolicy::rpc_connect()` is
  `("rpc connect", 10, 2 s)`, and `reconnecting_tcp_client.rs` says
  `tcp_stream_with_retry` retries "ten times with a two-second sleep". In the
  binary both (`0x2039060`/`0x4387f40` and `0x439fa90`/`0x4b399a0`) have the
  same `max(-1, 1)` bound, as do the three `NodePort::listen` instances.
- **Exhaustion text:** the lead's `Display` is
  `async_sleep_retry retries exhausted: {} [n_retries: {}]`. The binary's
  template has ` @@ [n_retries: `.

## Controls

`tests/test_height_retry_static.py` (21 tests) regenerates `records.json`.
It checks the `max(.., 1)` and attempt-index models. It refuses each of
these corruptions:

- The raw bound changed to 10.
- The record's 10 changed.
- The descriptor text changed.
- A read of `[rbx+0x3bb0]` planted.
- An extra `[rbx+0x3c30]` read planted.
- The retry or exhaustion template changed.
- The `n_tries` formatter's RELATIVE addend redirected.
- The zero-sleep branch changed.
- The `rpc connect` site's raw bound changed to 10.
- An extra `[rbx+0x1a8]` read planted in `0x2039060`.

The module passes with GNU binutils or with LLVM tools only on `PATH`; the
producer does not use either.

## Unresolved

- Why the records carry 10 (or -1 when `bpl` is 0) if no loop consumes it.
  A callee reaching the record through another path is not excluded.
- The pointer and bound slots of `0x22c54a0` (disp8, not censused) and the
  extra slot writes in the two other NodePort FDEs.
- What `0x2237090` and the formatter `0x26aaba0` do (named by shape only).
- Whether a callee reads the retry state through `rbx`-relative pointers
  passed elsewhere in the future.
