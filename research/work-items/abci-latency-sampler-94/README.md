# transport: node #94 ABCI latency sampler `0x3d22aa0` / `0x3d22920` / `0x3d22500` (backwards clock samples 0.0; row `apply_duration` uncapped; no-writer return; constructor takes a prefix and one f64)

Question: `0x3d22aa0`, `0x3d22920` and `0x3d22500` are the
`net_utils/abci_latency_sampler.rs` constructor, begin-block and commit
paths. What do they sample, and what does commit write? The can1357 lead
(`net_utils/abci_latency_sampler.rs`) skips a sample when the wall clock
runs backwards (`if let Some(duration)` / `let ... else { return }`), caps
the row's `apply_duration` at 60 s, takes a block-times root and a
`rotate_hourly` flag in its constructor, and flushes only on
`flush_on_commit`. Where does the binary differ?

- Component ID: `transport` (`docs/COMPONENTS.md`; path rule `net_utils/*`).
  `research/catalogue/seed-candidates.json` lists `0x3d22aa0`, `0x3d22920`,
  `0x3d22500`, `0x3d2258c` and `0x3d22971` as
  `net_utils/abci_latency_sampler.rs` seeds, plus the data seeds
  `0x5776558` and `0x5776568`.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for claims to test; no code, comments or names copied.
- Claim status: byte-level facts are observations; inferences are marked as
  such, and open questions are listed under Unresolved. This is partial
  `transport` research; no gate changes.
- Scope (seven windows, whole functions unless noted):
  - the elapsed helper `0x1447130` (`0x1447130..0x144727e`);
  - commit `0x3d22500` (`0x3d22500..0x3d228d9`, including both panic
    blocks);
  - begin `0x3d22920` (`0x3d22920..0x3d22a97`);
  - the constructor `0x3d22aa0` up to its return (`0x3d22aa0..0x3d22d0a`);
  - the row writer `0x3d24ff0` up to its error paths
    (`0x3d24ff0..0x3d25129`);
  - the head of the row serializer `0x3d22e10` (`0x3d22e10..0x3d22ee4`);
  - the head of the writer helper `0x13d1880` (`0x13d1880..0x13d18ac`).
  - Also: seven packed format templates, seven strings, four f64 constants,
    five panic Locations, 20 slots, and a whole-`.text` census of callers of
    the three entry points.
- Excluded:
  - the unwind paths;
  - the bodies of the sampler constructor `0x1403c30`, the sampler record
    `0x14027b0`, the block-times reporter constructor `0x1402050`,
    `signed_duration_since` `0x151d1b0`, the writer open `0x13d1720`, the
    line append `0x13d12a0`, the field serializers, and the date and hour
    Display functions;
  - the callers `0x432e4d0`, `0x4677fd0` and `0x474bfa0`.

## Reproduce

```sh
make verify
python3 tools/abci_latency_sampler_static.py --json > research/work-items/abci-latency-sampler-94/records.json
python3 -m unittest tests.test_abci_latency_sampler_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`), and the `.rela.dyn`
`R_X86_64_RELATIVE` and `R_X86_64_GLOB_DAT` entries. It never executes the
target. It needs only Python 3 (run here with 3.14.7 on macOS arm64; under
1 s). `records.json` is its complete output, and the test suite regenerates
it and compares the two.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has
7 windows (639 instructions, 2881 bytes), one for each checked byte window.
All 174 `records.json` VAs that fall inside a window are instruction starts
there. The tool refuses unless each of the 227 `FACTS` entries and each of
the 143 decoded call, branch and RIP-relative operands lies inside a checked
window. It also checks 20 slots (19 RELATIVE, one GLOB_DAT).

## Evidence

Times are chrono-style triples `(date, secs, frac)`: a 32-bit date word,
seconds of the day, and a fractional word. `self` offsets are from the
sampler object.

### Elapsed helper `0x1447130` (observation)

All three durations go through slot `0x576e8c0` → `0x1447130(&now, &tag)`.
The tag starts with the earlier time, followed by `{u32 1, u32 line}`, the
source file `0x5bcd1b`
(`/home/ubuntu/hl/code_Mainnet/net_utils/src/abci_latency_sampler.rs`) and
its length `0x42`. The lines are 54 (begin, block duration), 58 (begin,
backlog) and 66 (commit).

```text
if now < earlier:            ; date signed, then secs unsigned, then frac unsigned
    s = format("Time Sub {} {}", now, earlier)      ; template 0x1f9cb6
    if tag.flag & 1 and dword [0x577ab98] != 0:
        slot 0x576e8b8 (-> 0x4ee3b20) with 0x577ab80 / 0x577ab98
    drop s
    return 0.0
(secs, nanos) = signed_duration_since(now, earlier)   ; slot 0x576eaa0 -> 0x151d1b0
micros = secs * 1_000_000 + nanos / 1000              ; either overflow returns 0.0
return micros as f64 / 1e6
```

The nanosecond borrow (`nanos - 1e9` with `secs + 1`) only applies when
`secs < 0`, which this path cannot reach. The divide by 1000 is the multiply
`0x10624dd3` and shift 38; the tool checks that it truncates on a sample of
`[0, 1e9)`. The formatted message is not passed to the slot call.

### Begin `0x3d22920` (observation)

`rsi` is the block time and `dl` is `came_from_node`.

```text
now = wall clock                               ; slot 0x576e8a0 -> 0x151cba0
if dword [self+0x7d0] != 0:                    ; last_times is Some
    record(self+0x000, min(60.0, elapsed(now, [self+0x7dc])))   ; Location :55:41
if came_from_node:
    record(self+0x260, elapsed(now, block_time))                ; Location :58:34, no min
[self+0x7d0] = block_time; [self+0x7dc] = now
```

`record` is slot `0x576efb0` → `0x14027b0`, called with `esi = 1` and a
Location in `rdx`. The three record Locations are statics at `0x57193b8`,
`0x57193d0` and `0x57193a0`.

### Commit `0x3d22500` (observation)

`rsi` is the height.

```text
now = wall clock
if dword [self+0x7d0] == 0: return
apply = elapsed(now, [self+0x7dc])
record(self+0x4c0, min(60.0, apply))           ; Location :67:48
row = {height, apply, block_time [self+0x7d0], begin wall [self+0x7dc]}
if [self+0x768] == i64::MIN: return            ; writer is None
if now.secs >= 921600: panic "called `Result::unwrap()` on an `Err` value"   ; base/src/time.rs:62:44
if now.secs >= 90000:  panic "assertion failed: hour <= 24"                  ; base/src/hour.rs:12:13
if byte [self+0x7c8] == 1:                     ; hourly
    hour = now.secs / 3600
    if hour != byte [self+0x7c9] or now.date != [self+0x7b8]:
        open "{root}/hourly/{date}/{hour}"; [self+0x7b8] = date; [self+0x7c8] = 1; [self+0x7c9] = hour
elif now.date != [self+0x7b8]:
    open "{root}/{date}"; [self+0x7b8] = date
0x3d24ff0(writer, &now, &row)
[self+0x7bc] = now
if byte [self+0x7ca] and byte [0x5788312] and writer: writer helper
if writer: writer helper                       ; slot 0x576eaa8 -> 0x13d1880, both calls
```

The root is the 16 bytes at `self+0x728`, formatted by `0x14ddab0`. The date
and hour formatters are slots `0x576ea60` → `0x1454a00` and `0x576eb20` →
`0x13d95e0`. Each rotation opens a writer through slot `0x576eac0` →
`0x13d1720`, drops the old one with `0x3d20140`, and stores the new 0x50
bytes at `self+0x768`. The path templates are `0x1e9393`
(`{}/hourly/{}/{}`) and `0x1e938e` (`{}/{}`); the daily template ends where
the hourly one starts. The divide by 3600 is the multiply `0x91a2b3c5` and
shift 43, which the tool checks against `secs // 3600` below 921600.

### Row (observation)

`0x3d24ff0` is called only from `0x3d22839`. It allocates a 0x80-byte
buffer and serializes the row with `0x3d22e10`, which is called only from
`0x3d25041`. The serializer writes `{` and then four keyed fields:

| Key | Row offset | Field serializer |
| --- | --- | --- |
| `height` | `+0x00` | `0x3d264d0` |
| `block_time` | `+0x10` | `0x3d260d0` |
| `begin_block_wall_time` | `+0x1c` | `0x3d260d0` |
| `apply_duration` | `+0x08` | `0x3d26270` |

The row writer then appends `\n` and calls `0x13d12a0(writer, &now, bytes,
len)`.

### Constructor `0x3d22aa0` (observation)

The constructor reads `rdi` (the output), `rsi`/`rdx` (a prefix `&str`) and
`xmm0` (an f64). Each name is `format!` of the prefix with one suffix
template. Each sampler is built by slot `0x576efc8` → `0x1403c30(out, esi,
name, len, xmm0)`:

| Field | Name template | `xmm0` | `esi` |
| --- | --- | --- | --- |
| `+0x000` | `{}_block_duration` (`0x1fe9cf`) | 1.0 | 0 |
| `+0x260` | `{}_backlog_from_node` (`0x1ddb69`) | 1.0 | 1 |
| `+0x4c0` | `{}_begin_block_to_commit` (`0x1ef953`) | 0.06 | 0 |

After the third sampler is built, the constructor overwrites its first two
words with `1` and the f64 argument. `{}_block_times` (`0x1f245b`) goes to
slot `0x576ef10` → `0x1402050`, and the 0xb0-byte result is copied to
`self+0x720`. Finally, `[self+0x7d0] = 0`.

### Callers (observation)

The census finds no direct `e8` call to any of the three entry points. Each
is held by one RELATIVE slot and called through it (`ff 15`) from exactly
two sites:

| Entry | Slot | Call sites (containing FDE) |
| --- | --- | --- |
| constructor `0x3d22aa0` | `0x5776560` | `0x432e503` (`0x432e4d0`), `0x474bfe8` (`0x474bfa0`) |
| begin `0x3d22920` | `0x5776558` | `0x432e621` (`0x432e4d0`), `0x474c625` (`0x474bfa0`) |
| commit `0x3d22500` | `0x5776550` | `0x4678b5f` (`0x4677fd0`), `0x474d4af` (`0x474bfa0`) |

The lead's seed cluster `0x5776558..0x5776568` also covers `0x5776568`,
which holds `0x3d29040`; that function is not decoded here.

## Lead comparison

| Point | Binary | Lead |
| --- | --- | --- |
| Wall clock runs backwards | elapsed returns 0.0, which is sampled; commit still writes the row | sample skipped; commit returns before the row |
| Duration resolution | whole microseconds | nanoseconds (`Duration::as_secs_f64`) |
| Row `apply_duration` | uncapped elapsed value | `min(60, apply)` |
| Writer slot is None | returns after the sample, before the seconds checks and the row | no such case |
| Commit wall time | stored at `+0x7bc` and passed to the line append | not kept |
| Writer helper after the row | once, plus once more first when `+0x7ca` and global byte `0x5788312` are set; each call only if the writer slot is present | `flush()` only when `flush_on_commit` |
| Hourly mode | byte `[+0x7c8] == 1`; each hourly rotation writes 1 back and the daily branch never writes it | `rotate_hourly` constructor flag |
| Second-of-day checks | `base/src/time.rs:62:44` unwrap and `base/src/hour.rs:12:13` `hour <= 24` panics, only when a writer exists | two asserts naming this file, on every time conversion |
| Constructor | `(prefix, f64)`; constants 1.0 / 1.0 / 0.06 and flags 0 / 1 / 0; the f64 goes only into the third sampler | `(prefix, root, threshold, rotate_hourly)`; the same threshold for all three |

The JSON key names and their order match the lead. Its time encoding
(`{"day", "seconds_from_midnight", "nanos"}`) is not checked, because the
time serializer `0x3d260d0` is not decoded.

## Inference

- `0x1403c30`'s `xmm0` and `esi` arguments, and the `{1, f64}` written into
  the third sampler, look like per-sampler bucket parameters and an
  `Option<f64>` set to `Some(argument)`. Their meaning is not decoded.
- `0x13d1880` calls `0x13d1460` and then `0x14c3530`, whose head reads a
  buffer length at `+0x10` and an fd at `+0x1c` (the shape of a `BufWriter`
  flush). It then drops an io::Error with tag 1. This makes it likely a
  flush that discards its error, but the bodies are not decoded.
- The root, the hourly tag, the flag at `+0x7ca` and the first date at
  `+0x7b8` all live in the 0xb0 bytes built by `0x1402050` from
  `{prefix}_block_times`.
- `0x1447130` is shared: 72 `ff 15` sites call slot `0x576e8c0`.

## Unresolved

- The bodies of `0x1402050`, `0x1403c30` and `0x14027b0`.
- What sets `0x5788312`, and what the once slot at `0x577ab80` does.
- The time JSON encoding, and the line append `0x13d12a0`, which reads its
  own optional fields at `writer+0x38` / `+0x40`.
- The callers `0x432e4d0`, `0x4677fd0` and `0x474bfa0`, and the function
  `0x3d29040` in slot `0x5776568`.

## Controls

- `tests/test_abci_latency_sampler_static.py` checks:
  - the `elapsed`, `begin` and `commit` models: a backwards clock, equal
    times, microsecond truncation, a nanosecond borrow across days, capped
    and uncapped samples, the uncapped row, the no-writer return, daily and
    hourly rotation, both second-of-day panics, and one or two writer-helper
    calls;
  - the constructor samplers, the templates, the Locations, the elapsed
    callsite lines, the row keys and the caller census;
  - regeneration of `records.json`, and the CLI.
- Corruption tests (each must raise `EvidenceError`):
  - a removed commit cap and a changed 60.0 constant;
  - the daily template, a record Location line and the `hour <= 24` string;
  - the global-flag RELATIVE slot and an entry-point slot;
  - a planted `e8` call to begin and a planted `ff 15` call through its slot;
  - a row that no longer stores the raw elapsed value, an ungated first
    writer call, an elapsed error arm that does not return 0.0, and a
    swapped sampler constant;
  - a fact outside every window.
- Both toolchains: the module passes with GNU binutils on `PATH` and with
  only LLVM; the tool itself uses neither.
