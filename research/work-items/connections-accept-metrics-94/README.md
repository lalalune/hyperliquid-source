# node-runtime: node #94 instrumented accept loops `0x203f3e0` / `0x2041c60` (tokio-metrics poll counters; accept errors print to stdout and continue; IPv6 peers rejected in `0x2048f10`)

Question: `0x203f3e0` and `0x2041c60` are `node/connections.rs` accept loops
that poll the accept wrapper `0x2048f10`. What does each poll record, and
what happens on an accept error? The can1357 lead (`node/connections.rs`
`accept_*_stream_connections`) has no instrumentation on its accept loops,
returns on the first accept error (`accept().await?`), and accepts IPv6
peers. Where does the binary differ?

- Component ID: `node-runtime` (`docs/COMPONENTS.md`; path rule `node/*`).
  `research/catalogue/seed-candidates.json` lists `0x203f3e0` and `0x2041c60`
  as `node/connections.rs` seeds (lines 10 and 11), and lists `0x2048f10` as
  a `transport` seed (`net_utils/tcp/tcp_listener.rs`).
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for claims to test; no code, comments or names copied.
- Claim status: byte-level facts are observations; inferences are marked as
  such, and open questions are listed under Unresolved. This is partial
  `node-runtime` research; no gate changes.
- Companion packet: `connections-accept-loop-94` (PR #582) covers the
  uninstrumented twin loops `0x22c0d30` / `0x22c15e0`, which poll
  `0x22c47a0`. The error arm, the spawn helpers and the accept-poll logic
  have the same shape in both packets, but each packet checks its own bytes.
- Scope:
  - In both loops (twin shift `0x2880`): the poll entry and timing blocks
    (`0x203f3e0..0x203f626`), the resume block (`0x203f6d7..0x203f740`), the
    loop body (`0x203fb84..0x203fc82`), the Pending exit
    (`0x203fc82..0x203fde9`), the dispatch (`0x203fe36..0x203ffed`) and two
    panic blocks.
  - In the accept poll `0x2048f10`: the `accept4` call and io::Error
    classification, the WouldBlock readiness clear, registration and error
    results, the IPv4 gate, the Pending result and the fd -1 panic.
  - The kind formatter `0x4b6f890`, the head of the stdout print `0x4edba50`,
    and the label, task-name and flag stores in the spawn helpers.
  - The instrumented waker vtable `0x5691688`.
  - A whole-`.text` census of direct `e8` calls to `0x2048f10`.
- Excluded:
  - The first-run setup between `0x203f740` and `0x203f9fc`, which allocates
    state and builds an `abci_stream` name passed to `0x3d21f50`.
  - The waiter-list unlink after `0x203fc27`.
  - The unwind paths, where the twins use different drop slots.
  - The bodies of `0x4ee3800`, `0x4ee3730`, the waker functions, the handler
    futures, and `0x22b8310`, `0x288d0d0`, `0x288cab0` and `0x4f76f80`.
  - The IPv4 path after `0x2049715`.
  - The `select!`-style caller `0x2032ae0`.

## Reproduce

```sh
make verify
python3 tools/connections_accept_metrics_static.py --json > research/work-items/connections-accept-metrics-94/records.json
python3 -m unittest tests.test_connections_accept_metrics_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`), and the `.rela.dyn`
`R_X86_64_RELATIVE` and `R_X86_64_GLOB_DAT` entries. It never executes the
target. It needs only Python 3 (run here with 3.14.7 on macOS arm64; about
1 s). `records.json` is its complete output, and the test suite regenerates
it and compares the two.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has
30 windows (873 instructions), one for each checked byte window. All 232
`records.json` VAs that fall inside a window are instruction starts there.
The tool refuses unless each of the 162 `FACTS` entries and each of the 177
decoded call, branch and RIP-relative operands lies inside a checked window.
It also checks:

- twelve slots (ten RELATIVE, two GLOB_DAT);
- the four entries of the waker vtable;
- four panic Locations.

## Evidence

### Twins (observation)

The FDEs `0x203f3e0` and `0x2041c60` have the same length (`0xd2a`). All
1777 checked bytes of the eight twin window pairs are equal, except inside
the 66 rel8/rel32 operands. In those operands:

- Every target inside the loop's own FDE moves by `+0x2880`.
- Every external target is the same in both loops.
- The one exception is the spawn call: `0x203ffe3` calls `0x225e860`
  (label `validator`, flag 0) and `0x2042863` calls `0x225e3b0` (label
  `gossip`, flag 1). Both helpers store the task name
  `handle_stream_connection`.

### Instrumented poll (observation; validator twin addresses)

`task = [state]` and `monitor = [task+0x30]`. The clock is
`0x4ee3800(1)`. `d(a, b)` is `0x4ee3730`, a saturating difference that
returns 0 when it gives None, converted to nanoseconds. All monitor updates
are `lock inc` or `lock add`.

```text
now = clock()                                   ; 0x203f3fc
created = ([task+0x38], [task+0x40])
if byte [state+0x230] == 0:                     ; first poll
    [state+0x230] = 1
    monitor[0x58] += d(now, created); monitor[0x18] += 1
woke = swap([task+0x10], 0)                     ; ns since created, set by the waker
if [state+0x228] < woke:                        ; idle
    monitor[0x20] += 1; monitor[0x60] += woke - [state+0x228]
if woke != 0:                                   ; scheduled
    monitor[0x28] += 1
    delay = d(now, created + woke)              ; created + woke overflow panics (std time.rs:429:33)
    if delay < Duration(monitor[0xa0], monitor[0xa8]): monitor[0x48] += 1; monitor[0x80] += delay
    else:                                             monitor[0x40] += 1; monitor[0x88] += delay
    monitor[0x68] += delay
wrap the waker with vtable 0x5691688            ; 0x203f6e2
start = clock()                                 ; 0x203f713
match byte [state+0x222]: 0 -> first run, 3 -> resume at 0x203fb92,
                          else panic node/src/connections.rs:186:84
... inner loop; on accept tag 3 (Pending):
[state+0x222] = 3
end = clock()                                   ; 0x203fc8e
[state+0x228] = d(end, created)
poll = d(end, start)
if poll < Duration(monitor[0x90], monitor[0x98]): monitor[0x30] += 1; monitor[0x70] += poll
else:                                              monitor[0x38] += 1; monitor[0x78] += poll
return 1                                        ; Pending
```

The idle subtraction has a borrow check that panics at
`tokio-metrics-0.3.1/src/task.rs:2483:23`. It cannot fire after the `<` test
above. The waker vtable at `0x5691688` holds `0x1f6ad20`, `0x219a6d0`,
`0x219a6e0` and `0x219a6b0`.

### Accept error and spawn (observation)

On accept result tag 2, the loop prints the template `0x1fb0d4`,
`{} ERROR >>> {} @@ node failed to accept {} connection: {}\n\n`, to stdout
through slot `0x576e968` (→ `0x4edba50`, label `stdout`). The arguments are:

- the wall-clock time `0x151cba0`, formatted with its own copy of
  `%Y-%m-%dT%H:%M:%S%.3fZ` at `0x3c42d1`;
- the lazy `&str` at `0x577ab58`;
- the kind byte `[state+0x220]` (1 → `gossip`, otherwise `validator`);
- the error.

It then drops the error and jumps to `0x203fb84`, the accept poll. The only
calls in the error arm are the clock, the print, a free and the error drop.

On any other tag, the loop clones `state+0xc8` (`0x22b8310`), spawns the
handler, and jumps back.

### Accept poll `0x2048f10` (observation)

| Case | Path | Result tag |
| --- | --- | --- |
| listener fd is -1 | `0x20497b4` panic, Location `tokio-1.44.2/src/io/poll_evented.rs:288:26` | none |
| `accept4` (`0x3cd6220`) error, WouldBlock | io::Error repr table `0x3c3d58`: kind byte 13 (SimpleMessage, Custom), Os 11 (EAGAIN) or Simple kind 13 → `0x2049425`, clears readiness bits | none from this block |
| `accept4` error, any other | `0x20495a5` → `0x288d0d0` | 2 |
| Tokio registration `0x4f76f80` (interest 3) fails | close the fd (GLOB_DAT `close`) | 2 |
| Tokio context shutting down (block `0x2049583`; its entry is not decoded) | message `A Tokio 1.x context was found, but it is being shutdown.` | 2 |
| peer `SocketAddr` tag bit 0 set (V6) | `0x288cab0("ip not v4")` (own copy at `0x3c4be5`), close fd if not -1 | 2 |
| not ready | `0x20496f4` | 3 |

The census finds direct calls to `0x2048f10` only from:

- `0x203fbac` in `0x203f3e0`;
- `0x204242c` in `0x2041c60`;
- nine sites in `0x2032ae0`.

No RELATIVE slot holds its address.

## Lead comparison

| Point | Binary | Lead |
| --- | --- | --- |
| Instrumentation | every poll of both loops updates up to 14 monitor counters (first poll, idle, scheduled, short/long delay, fast/slow poll) | none on `accept_*_stream_connections` |
| Idle | `woke - last poll end`, counted only when the waker fired after the last poll ended | `TimedPollState::begin_poll` (`node/node.rs`, a different task): `now - last_polled_at` |
| First-poll delay | `now - created` (task Instant at `[task+0x38]`) | `now - first_scheduled_at` |
| Delay / poll thresholds | two Duration thresholds at monitor `+0xa0` and `+0x90` split the counters | not modelled |
| Accept error | stdout `ERROR >>>` line, then poll again | `accept().await?` returns the error |
| IPv6 peer | rejected with `ip not v4` | accepted |

## Inference

- The layout matches tokio-metrics 0.3.1 `Instrumented<T>::poll` with a
  `TaskMonitor`. Likely field names are `first_poll_count` /
  `total_first_poll_delay`, `total_idled_count` / `total_idle_duration`,
  `total_scheduled_count` / `total_scheduled_duration`, short/long delay
  counts and durations, and fast/slow poll counts and durations, with
  `long_delay_threshold` at `+0xa0` and `slow_poll_threshold` at `+0x90`.
  Only the crate path (in the panic Location), the offsets and the
  arithmetic are checked; the field names are not.
- `0x4ee3800(1)` is probably `clock_gettime(CLOCK_MONOTONIC)`, that is
  `Instant::now`.
- These loops are the instrumented versions of the `0x22c0d30` /
  `0x22c15e0` twins. Which listener each pair serves is not decoded.

## Unresolved

- The threshold values, and who reads the monitor.
- The first-run setup, including the `abci_stream` name and the value 600
  passed to `0x3d21f50`.
- The kind byte value each loop holds.
- The IPv4 path after `0x2049715`.
- The `0x2032ae0` caller.

## Controls

- `tests/test_connections_accept_metrics_static.py` checks:
  - the `poll_metrics` model (first poll, idle with a short delay, a delay
    exactly at the threshold counted as long, no wake, a slow poll);
  - the counter offsets, the Locations, the twin layout, the error-arm
    template, the accept-poll cases and the caller census;
  - regeneration of `records.json`, and the CLI.
- Corruption tests (each must raise `EvidenceError`):
  - a slow-poll threshold offset, a counter offset, an error arm that
    returns, and a removed IPv4 gate;
  - the template, the `ip not v4` string, a jump-table entry and the
    tokio-metrics Location line;
  - the waker vtable, the print RELATIVE slot and the `close` GLOB_DAT
    symbol;
  - twin bytes that differ outside an operand;
  - a planted `e8` call to `0x2048f10` from another function.
- Both toolchains: the module passes with GNU binutils on `PATH` and with
  only LLVM; the tool itself uses neither.
