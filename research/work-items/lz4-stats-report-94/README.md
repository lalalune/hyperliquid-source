# transport: node #94 LZ4 stats report loops `0x3d21990` / `0x3d12780` (one total over every entry and both directions; rows and total written through a rotating block-times reporter; no output bytes or elapsed time in a row)

Question: `0x3d21990`, `0x3d12780` and `0x3d2ba50` are
`net_utils/tcp/lz4_stats.rs` seeds. What does the report path do every
300 s, and where do the results go? The can1357 lead
(`net_utils/tcp/lz4_stats.rs`) has `report_once` build one inbound and one
outbound report from the drained snapshots with saturating sums. Each of
its snapshots keeps output bytes and an elapsed time, and its output is
`tcp_lz4_stats ...` text for tracing. It describes `0x3d12780` as the outer
task that sleeps 300.0 s between reports, and `0x3d21990` as one report. Where does the
binary differ?

- Component ID: `transport` (`docs/COMPONENTS.md`; path rule `net_utils/*`).
  `research/catalogue/seed-candidates.json` lists `0x3d12780`,
  `0x3d21990`, `0x3d230c0`, `0x3d2a730` and `0x3d2ba50` as
  `net_utils/tcp/lz4_stats.rs` seeds.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for claims to test; no code, comments or names copied.
- Claim status: byte-level facts are observations; inferences are marked as
  such, and open questions are listed under Unresolved. This is partial
  `transport` research; no gate changes.
- Companion work: open PR #592 binds the counter writer `0x3d2a730` and
  the drain `0x3d230c0`. This packet re-checks only the part of
  `0x3d230c0` that the report path depends on. Open PR #625 covers the ABCI
  latency sampler, which uses the same reporter constructor `0x1402050`.
  Each packet checks its own bytes.
- Scope (nine windows):
  - `0x3d21990`: the head and state dispatch (`0x3d21990..0x3d219fe`) and
    the loop with its slow paths (`0x3d21a6f..0x3d21ce5`);
  - `0x3d12780`: the report block (`0x3d12afc..0x3d12cf3`) and its slow
    paths (`0x3d12e18..0x3d12e7e`);
  - the collect `0x3d2ba50` (`0x3d2ba50..0x3d2bc53`);
  - the per-entry part of `0x3d230c0` (`0x3d23159..0x3d2328b`);
  - the rows writer `0x3d1dde0` (`0x3d1dde0..0x3d1e0f2`) and the total
    writer `0x3d1e500` (`0x3d1e500..0x3d1e7ee`);
  - the entry `0x3d27940` (`0x3d27940..0x3d27995`).
  - Also: two packed path templates, five strings, two conversion
    constants, six panic Locations, 18 RELATIVE slots, and a whole-`.text`
    census of direct callers.
- Excluded:
  - the unwind paths;
  - the tokio-metrics bookkeeping in `0x3d12780` outside its report block;
  - the bodies of the sleep polls `0x3d1e830` / `0x3d0eee0`, the row
    serializers `0x3d24610` / `0x3d24130`, the reporter constructor
    `0x1402050`, the runner `0x3d1f6b0` and the once initialiser;
  - the table walk at the head of `0x3d230c0`.

## Reproduce

```sh
make verify
python3 tools/lz4_stats_report_static.py --json > research/work-items/lz4-stats-report-94/records.json
python3 -m unittest tests.test_lz4_stats_report_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`), and the `.rela.dyn`
`R_X86_64_RELATIVE` entries. It never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; about 1 s). `records.json` is
its complete output, and the test suite regenerates it and compares the two.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has
9 windows (805 instructions, 3787 bytes), one for each checked byte window.
All 225 `records.json` VAs that fall inside a window are instruction starts
there. The tool refuses unless each of the 238 `FACTS` entries and each of
the 184 decoded call, branch and RIP-relative operands lies inside a checked
window.

## Evidence

### Report loops (observation)

`0x3d21990` and `0x3d12780` run the same report block. `0x3d21990`
enters a tracing span (`[self] != 2`, vtable `+0x60`) on each poll and
exits it (`+0x68`) on Pending. Its state byte `+0x178` is 0 to start, 3
to resume, and anything else panics at `net_utils/src/tcp/lz4_stats.rs:81:42`.
`0x3d12780` is the tokio-metrics instrumented twin; its state, sleep and
totals sit at different offsets.

```text
loop:
    poll sleep (0x3d21990: self+0xd8 via 0x3d1e830; 0x3d12780: self+0xb8 via 0x3d0eee0)
    Pending -> return
    total0 = total1 = total2 = 0
    once 0x5786568 initialises the table; lock parking_lot mutex 0x5786530
    rows = 0x3d2ba50(iterator over table 0x5786538 / 0x5786540 / 0x5786550, &totals)
    unlock
    if rows.len != 0: 0x3d1dde0(&now, reporter, rows)          ; takes the Vec
    if total0 != 0:  0x3d1e500(&now, reporter, {total0, total2, total1 / total0})
    free rows if it was empty
    sleep = 300.0; re-arm
```

The reporter is `self+0x28` in `0x3d21990`. The ratio uses the u64-to-f64
conversion constants at `0x203e80` and `0x202ea0` (2^52, 2^84).

### Collect and drain (observation)

`0x3d2ba50` calls `0x3d230c0` with the totals at `iterator+0x40` until the
returned row has byte 6 == 2. It collects 0x20-byte rows into a `Vec` with
a first capacity of 4 (0x80 bytes), growing through `0x3d28c00`.

For each table entry, `0x3d230c0`:

1. swaps its three counters to zero (`xchg [arc+0x10]`);
2. adds counter 0, 1 and 2 to total 0, 1 and 2, panicking on a carry at
   `lz4_stats.rs:96:21`, `:97:21` and `:98:21`;
3. **only then** skips the entry when counter 0 == 0 or key byte 6 == 2,
   moving on to the next entry;
4. otherwise returns the row `{key u32, key u16, key byte 6, key byte 7,
   counter 0, counter 2, counter 1 / counter 0}`.

So the totals include every drained entry: both values of key byte 6, and
entries whose counter 0 was zero.

### Writers (observation)

The two writers have the same structure. They differ in the row serializer
(`0x3d24610` for the rows, `0x3d24130` for the total), and the rows writer
also frees the `Vec`. `r` is the reporter.

```text
now = wall clock                                 ; slot 0x576e8a0
if [r+0x48] == i64::MIN: (rows: free) return      ; writer is None
if now.secs >= 921600: panic base/src/time.rs:62:44 (Result::unwrap)
if now.secs >= 90000:  panic base/src/hour.rs:12:13 (hour <= 24)
if byte [r+0xa8] == 1:  rotate to "{root}/hourly/{date}/{hour}" when the hour or date changed
elif date != [r+0x98]:  rotate to "{root}/{date}"
serialize(writer, &now, row)
[r+0x9c] = now
if byte [r+0xaa] and byte [0x5788312] and writer: writer helper (slot 0x576eaa8), once
```

### Entry (observation)

`0x3d27940`, held only by the RELATIVE slot `0x5786520`, builds the
reporter with `0x1402050("tcp_lz4_stats", 13)`. It then calls `0x3d1f6b0`
with `"lz4_stats"` (length 9), the reporter and bytes `+0x168 = 0`,
`+0x170 = 1`.

### Callers (observation)

| Function | Direct callers (containing FDE) |
| --- | --- |
| `0x3d21990` | `0x3d1323c` (`0x3d12f20`) |
| `0x3d12780` | `0x3cfdcd6` (`0x3cfdc40`) |
| `0x3d2ba50` | `0x3d21b4c`, `0x3d12bed` |
| `0x3d230c0` | `0x3d2ba70`, `0x3d2bbb0` |
| `0x3d1dde0` | `0x3d21b7a`, `0x3d12c31` |
| `0x3d1e500` | `0x3d21bf1`, `0x3d12cb1` |

No RELATIVE slot holds any of these. `0x3d27940` has no direct caller.

## Lead comparison

| Point | Binary | Lead |
| --- | --- | --- |
| Totals | one total over every drained entry and both directions, including entries with counter 0 == 0 | one report per direction (`None` when its input is 0), summed over snapshots, which are dropped when their input is 0 |
| Sum overflow | panics at `lz4_stats.rs:96:21` / `:97:21` / `:98:21` | `saturating_add` |
| Total row | `{total0, total2, total1 / total0}`, written only when total0 != 0 | input, output, samples and ratio per direction |
| Per-entry row | key, counter 0, counter 2, counter 1 / counter 0 | also output bytes and `elapsed_secs` |
| Output | rotating reporter files from `0x1402050("tcp_lz4_stats")`, `{root}/{date}` or `{root}/hourly/{date}/{hour}` | `tcp_lz4_stats ...` text for tracing |
| Missing writer | each writer returns before the seconds checks | not modelled |
| Loop structure | `0x3d21990` and `0x3d12780` are each a full loop that sleeps 300.0 s and runs the report; `0x3d12780` does not call `0x3d21990` (its only direct caller is in `0x3d12f20`) | `0x3d12780` is the outer task with the 300.0 s sleep; `report_once` (`0x3d21990`) does one report |

The lead's own comment gives the 0x20-byte record as key, input, samples
and ratio, which matches the row stores. Its struct adds the two fields
that are not stored.

## Inference

- If counter 0, 1 and 2 are input bytes, output bytes and samples (the
  lead's order), then the rows and the total carry input, samples and
  output/input. Which counter is which is not checked here.
- The writers are the same append routine as the ABCI latency sampler's
  block-times reporter (#625), with the reporter at offset 0 instead of
  `+0x720`: the root, writer, date, time, hour tag and flag offsets all
  match.
- The f64 300.0 stored at the sleep slot is the sleep length in seconds.
- Key byte 6 holds the direction (lead: `direction << 48`). The `== 2` test
  matches the row's None tag, so a direction byte of 2 could not be
  returned.

## Unresolved

- The JSON written by `0x3d24610` and `0x3d24130`.
- The sleep polls, the runner `0x3d1f6b0` and who drives it.
- The callers `0x3d12f20` and `0x3cfdc40`, and which loop runs in which
  process.
- The reporter's root, hourly tag and flag values set by `0x1402050`.

## Controls

- `tests/test_lz4_stats_report_static.py` checks:
  - the `drain` / `tick` model: totals over both directions, a zero-input
    entry that still counts, a byte-6 == 2 entry that is skipped but
    counted, the row fields, an empty tick, and which total overflows
    first;
  - the `append` model: a missing writer, daily and hourly rotation, one
    or zero writer-helper calls, and the hour panic;
  - the loop offsets, the drain order and Locations, the writers, the
    callers and the templates;
  - regeneration of `records.json`, and the CLI.
- Corruption tests (each must raise `EvidenceError`):
  - the 300.0 period and a removed filter branch;
  - the hourly template, an overflow Location line, the `tcp_lz4_stats`
    string and a conversion constant;
  - the entry RELATIVE slot and a planted `e8` call to the total writer;
  - a filter branch that no longer skips, an ungated total row, a
    twin-loop total at the wrong offset, a second writer-helper call, and a
    fact outside every window.
- Both toolchains: the module passes with GNU binutils on `PATH` and with
  only LLVM; the tool itself uses neither.
