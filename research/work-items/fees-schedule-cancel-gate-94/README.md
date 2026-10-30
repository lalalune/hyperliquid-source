# fees: what the gate behind the scaled_vlm.rs and raw_vlm.rs overflow records decides

- Component ID: `fees` (path rules `l1/raw_vlm.rs`, `l1/scaled_vlm.rs`).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only).
- Claim status: observation for bytes, decoded instructions, evaluated outcomes and message text;
  inference where marked; unresolved items are listed at the end.
- Scope included: the three wrappers, the three gate copies, the insert function, and the three
  chrono helpers they call. Scope excluded: the hash map internals of the two volume lookups, B-tree
  node splitting, the overflow hook body, the code that fires a scheduled cancel, and any fee rate.

## Reproduce

```sh
python3 tools/fees_schedule_cancel_gate.py --out research/work-items/fees-schedule-cancel-gate-94
python3 -m unittest tests.test_fees_schedule_cancel_gate
(cd research/work-items/fees-schedule-cancel-gate-94 && sha256sum -c MANIFEST.sha256)
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool
checks the input SHA-256 first and fails on any other file. It starts no external program, so no
binutils version can change its output. It does not run the node or visor: decoded instructions are
interpreted in Python. A full run takes under a minute. The output hashes are in `MANIFEST.sha256`.

## Evidence

All addresses are ELF virtual addresses. Function ranges come from `.eh_frame_hdr` and each FDE body,
and the decoder must land on each FDE end (`evidence.json`, `functions`).

### Where the question comes from

The panic Location records for these files are `l1/src/scaled_vlm.rs:15:21` (`0x56eb3e8`) and
`l1/src/raw_vlm.rs:17:21` (`0x56eb430`). `location_sites` gives their LEA sites from byte patterns: 20
and 14 sites, and the 14 functions holding the raw sites all hold scaled sites too. `0x2721260` is one
of them. The
reference tree calls it `l1_raw_vlm__sub_daily_exchange_vlm_gate_mono_a` and builds its daily volume
rollover model in `l1/scaled_vlm.rs` on it. This packet tests that model.

### Structure

| Copy | Wrapper | Gate | Insert | Dex vector ptr/len | User map root/height |
|---|---|---|---|---|---|
| a | `0x1e5fc40` | `0x2721260` | `0x2878880` | `+0x5c0`/`+0x5c8` | `+0x39a8`/`+0x39b0` |
| b | `0x4bffbc0` | `0x4d260c0` | `0x49560c0` | `+0x5c0`/`+0x5c8` | `+0x39a8`/`+0x39b0` |
| c | `0x4bffc70` | `0x4d266c0` | `0x49560c0` | `+0x1040`/`+0x1048` | `+0x4428`/`+0x4430` |

Each gate has 344 instructions and 1522 bytes. Across decoded operands, a and b differ only in branch
targets and the insert call. c differs from a in 7 instructions, all field offsets, shown in
`copy_comparison_against_a`. RE-010 lists `0x1e5fc40` as the first call of action tag 18,
`scheduleCancel`.

### Decision order

Input is an optional millisecond time and a 20-byte user. Outcomes, in the order they are checked:

1. Wrapper: time present and above `0xccccccccccccccb`: tag `0x13f`, message `Invalid input number`.
   The gate is not called.
2. Sum: for each element of the dex vector (stride `0x2f0`, map at `+0xf8`), the lookup at
   `0x36f57f0` gives a value with scaled volume at `+0x40` and raw volume at `+0x48`. The base lookup
   (slot `0x5773170`, map at `state+0x80`) gives scaled at `+0` and raw at `+8`. Every add that carries
   calls the overflow hook with its Location, and the total stays at `u64::MAX`. The per-dex adds use
   `l1/src/qtys/impl_ntl.rs:664:1`, the base adds use the two records above.
3. Raw is only checked: the base step tests for carry and calls the hook, and the raw total is never
   used again.
4. Scaled total below 100000000: tag `0x10e`, with `total / 100.0` as f64 payload. `cvtsi2sd` is
   64-bit. The message is `Cannot set scheduled cancel time until enough volume traded. Required: $`,
   placeholder, `. Traded: $`, placeholder, `.`. Its first argument is the immediate
   `0x412e848000000000`, which is 1000000.0.
5. Time absent: if the user has a map entry, the date dword of its value becomes 0. Result ok. No
   entry is created.
6. Time present: floor division gives days, seconds and nanoseconds. A day count of `0x7ff506c5` or
   more, or a date the helper `0x151f6f0` refuses, gives tag `0x85`, `Cannot create Time from input`.
   The last accepted time is 8210266876799999 ms, which is 262142-12-31T23:59:59.999.
7. State time at `+0x60` (date dword, seconds, nanoseconds) plus 5 seconds. `edx` = 5 and `ecx` = 0
   go to the real helper `0x15206e0`, and the day carry to the real helper `0x151f870`. If that date
   leaves the range, the panic text is `` `NaiveDateTime + TimeDelta` overflowed `` at chrono-0.4.38
   `naive/datetime/mod.rs:1631:38`.
8. The deadline must be later than that sum, compared as date (signed), seconds, nanoseconds.
   Otherwise tag `0x10c`, `Scheduled cancel time too early, must be at least 5 seconds from now.`
9. The B-tree keyed by 20-byte user is searched, and the entry is inserted if absent with a zero
   first word. If that u64 is above 9: tag `0x10d`, `Too many scheduled cancels triggered for the day.
   Limit is `, placeholder, `.`, with argument 10 read from `0x20ac78`.
10. The value's date, seconds and nanoseconds are written. Result ok (`0x186`, wrapper byte `0xd`).
    The first u64 is not changed here.

The value is 24 bytes: u64, date dword, seconds, nanoseconds. Node layout from the same code: values
at `+8`, keys at `+0x110`, length at `+0x1ee`, edges at `+0x1f0`.

### Against the reference

`reference-diff.tsv` lists 9 rows. The main ones:

- `DAILY_UPDATE_DELAY_DAYS = 5` with "five-day chrono delta" (`l1/scaled_vlm.rs:55`) is not supported.
  The 5 is a seconds field. The vectors cross the boundary at +5000 and +5001 ms, and the message says
  5 seconds.
- `MAX_DAILY_SCALED_VLM_ENTRIES` (`l1/scaled_vlm.rs:51`) is described as a per-user map of dates. The
  binary compares one u64 in a value keyed by user, and this function never writes it.
- `18_schedule_cancel.rs` is much closer: same six result codes, same order, same clear behaviour.
  It differs in the deadline test (`deadline_ms <= now_ms`, no 5 seconds), in what is stored (raw
  milliseconds) and in the range predicate at line 160, which rejects every time the binary accepts.

## Inferences

- The function is the scheduleCancel admission check, not a daily volume update. Basis: the four
  message texts and the action tag in RE-010. It reads volume and writes no volume.
- `scaled total >= 100000000` means one million dollars of traded volume. Basis: `Required: $` with
  1000000.0, and the payload divided by 100.
- The first u64 of the map value counts triggered cancels for a day. Basis: the message text only.
  Nothing in this packet writes it.
- Chains a, b and c look like copies of one source function for different state layouts. Why there
  are two layouts was not investigated.
- For the fees task "time-window rollover": this path contains no rollover of fee volume, so the
  reference's daily rollover constants need other evidence. Other code may still have such a rollover.

## Implementation and comparison

Not yet implemented. There is no Rust code here, so no build or binary comparison exists.

The comparison is between an evaluator and a separate closed-form model in the same tool (`model`).
Real bytes run for the three wrappers, three gates, both inserts, `0x151f6f0`, `0x15206e0`,
`0x151f870` and `0x14509a0`. Stubs replace: both volume lookups, the overflow hook, memcmp, the
allocator, the leaf insert (`0x1aeca60`, `0x41ffed0`), and the formatter and error box inside
`0x14509a0`. Stubs spoil caller-saved registers, state and node memory faults on a read of an unset
byte, and the stack is poisoned. The test map is read back by a separate walker, so a write to another
entry would show.

## Results and limitations

`evidence.json` carries the metrics, with these denominators:

- 1066 vectors on each of 3 chains, 3198 evaluations, 0 mismatches. Outcomes: ok 1716, `0x10e` 954,
  `0x10c` 396, `0x10d` 54, `0x85` 42, `0x13f` 30, panic 6.
- Gate coverage: 342 of 344 instructions in each copy. The 2 others are the block after the tag-0 arm
  of `0x14509a0`, which is linear and always writes tag 1. The tool fails if anything else stays
  unexecuted.
- One-way branches in each copy: 2. One is that tag-0 test. The other is the guard on the seconds
  carry at gate offset `0x2ba`, which needs a carry beyond one day and cannot occur with +5 s; its
  panic block runs through the other branch.
- The insert functions leave 7 of 76 instructions unexecuted: allocation failure and full-node panic.
- Helper instructions not executed: 11 of 92, 31 of 145, 38 of 87. Those helpers are compared only
  through this gate's inputs, not over their whole domains.

Limits:

- Volume sums run on chosen values, not all inputs. The boundaries were picked by reading the code.
- The lookups are stubs. Byte checks fix their entry sizes (120 and 88) and value offset (24). A miss
  returns a lazily built static default, and whether it is all zero was not checked, so a miss is not
  claimed to count as zero volume.
- The overflow hook is stubbed as a function that returns. That behaviour is taken from the code after
  each call, which goes on to use the saturated value.
- A state time with nanoseconds at or above 1e9 is tested, but whether state can hold one is unknown.
- Mutation results are in the PR description, and 15 of them are permanent tests.

No progress gate is requested.

Next question: which function writes the first u64 of the map value and resets it, and does it use
the stored date at `+8` or the state day? That is where "for the day" gets its meaning. A raw scan
for `0x39a8` shows many candidates, and that scan is not evidence.
