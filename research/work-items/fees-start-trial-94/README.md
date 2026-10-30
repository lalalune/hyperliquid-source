# fees: the start fee trial writer in node #94

- Component ID: `fees` (first task: maker/taker fee formulas and time-window rollover; this packet fixes how a user's fee rate row is
  replaced by a trial, and which dates that stores).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only, nothing copied).
- Claim status: observation for bytes, decoded instructions, evaluated outcomes, status texts and calendar tables; inference where
  marked; unresolved items are listed at the end.
- Scope included: `0x3744020` and `0x37463f0` in full, the day helper `0x1450810`, the action validator `0x3c058f0` and its fourth
  field helper `0x374fe60`. Run as real dependencies, with no new claim: the row reader `0x3743df0`, the calendar add `0x151f870`, the
  table entry path `0x3596da0` and `0x379a610`. Scope excluded: the hash `0x399c7a0`, the decimal parser `0x3799510` and its conversion
  `0x4ead680`, the drop `0x3762510`, the table reserve `0x357d310` (all stubs), the handler bodies beyond the pinned bytes, the code that
  clears or expires a trial, and node #115.

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 tools/fees_start_trial.py --out research/work-items/fees-start-trial-94
python3 -m unittest tests.test_fees_start_trial
(cd research/work-items/fees-start-trial-94 && sha256sum -c MANIFEST.sha256)
# optional, for a human reader only; no evidence file uses this
objdump -d -M intel --start-address=0x3744020 --stop-address=0x3744547 artifacts/node/94/hl-node
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input SHA-256 first and
fails on any other file. It starts no external program, so no binutils version can change its output. Sections and FDEs come from
`tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or visor: decoded instructions are interpreted in
Python. A full run takes about 90 seconds and writes `evidence.json`, `vectors.tsv`, `mutations.tsv`, `instructions.tsv` and
`reference-diff.tsv`.

## Evidence

All addresses are ELF virtual addresses. Function ranges come from `.eh_frame`, and the decoder must land on each FDE end
(`evidence.json`, `functions`).

### Where the code is

| Function | FDE range | Instructions | Role here |
|---|---|---|---|
| `0x3744020` | `0x3744020..0x3744547` | 274 | writer: the gates, then the row writes |
| `0x37463f0` | `0x37463f0..0x3746564` | 91 | builds the new row |
| `0x1450810` | `0x1450810..0x145085b` | 17 | adds whole days to a date |
| `0x3c058f0` | `0x3c058f0..0x3c05c22` | 166 | turns four strings into four `f64` |
| `0x374fe60` | `0x374fe60..0x374ff96` | 72 | the same step for the fourth string, out of line |

Slot `0x5773920` holds `0x3744020` and has three call sites, each in a 698-byte handler body: `0x21e0306` in `0x21e00b0`, `0x46777d6`
in `0x4677580`, `0x4677a96` in `0x4677840` (`evidence.json`, `writer_callers`, `handler_copies`). `0x4677580` decodes to the same
instructions as `0x21e00b0`. `0x4677840` differs in 10 displacements, all by `0xa80`, so it serves an exchange shape 0xa80 bytes
larger before those fields. The offsets below are those of `0x21e00b0`.

The arguments are `(out, tracker, sender, time, action, linked)`. At `0x21e02de` the tracker is
exchange `+0x5d0`, and the time is the 12 bytes copied from exchange `+0x60`. `0x3744203` reads only the first word of it.

Before the call the handler rejects byte 3 at exchange `+0x8f2` with status `0x8d`, then a sender found in the table at `+0x3810` with
status `0xdb`. `linked` is null or the value of the sender in the table at `+0x37e0`: a pointer at `+8`, a count at `+0x10`, and a
20-byte address at `+0x18` of each 0x40-byte element.

### The gates, in order

Every status text comes from the Display table at `0x59a8d0` (`evidence.json`, `status_text`).

| Order | Test | Status | Text |
|---|---|---|---|
| 0 | row of the sender is read | | |
| 1 | byte tracker `+0x168` (`trials_disabled`) is non-zero | `0x138` | Fee trials are disabled. |
| 2 | row date `+0x68` is non-zero | `0x134` | Fee trial has already started. |
| 3 | a string is longer than 100 bytes | `0x143` | Invalid input length |
| 3 | a string does not parse | the parser's | payload copied through |
| 3 | a decimal does not convert to `f64` | `0xab` | Error converting decimal to float |
| 4 | the four rates are not allowed | `0x135` | Fee trial rate does not exist. |
| 5 | cooldown date set and date + 90 days is after today | `0x137` | Fee trial ended too recently. |
| 6 | the row would not change | `0x136` | Fee trial rates are already met. |
| 7 | writes | `0x186` | |

A reject writes nothing: the table and tracker are compared byte by byte after each call.

Strings are read in the order at `+0x18` (string at `+0x20`, length `+0x28`), `+0`, `+0x48`, `+0x30`, and go to rate slots 0 to 3. The
serde names in `.rodata` are, in order, `perpAddBaseRate`, `perpCrossBaseRate`, `spotAddBaseRate`, `spotCrossBaseRate`.

Step 4 scans the 0x30-byte rows at tracker `+8` (count `+0x10`) for all four rates, using exact `f64` equality, so a NaN never matches.
If no row matches but one row matched slots 0 and 2, the second `f64` of a 0x10-byte override row at tracker `+0x20` (count `+0x28`)
must equal both slot 1 and slot 3. The first `f64` of an override row is not read.

### Row builder

`0x37463f0` takes the tracker, the old row, the requested rates and the end date. With the 0x10-byte rows `(threshold, discount)` at
tracker `+0x38` (count `+0x40`) and `v` the old row word at `+0x20`:

```text
discount = 0, or the discount of the last row before the first threshold > v
keep     = 1 - discount                        (1.0 read at 0x20a730)
scaled_i = requested_i * keep  if requested_i > 0  else requested_i
effect   = any(old_i - scaled_i > 0)
new_i    = min(old_i, scaled_i)
```

The new row is `new[4], v, requested[4], old[4], date, old multiplier`, at `+0`, `+0x20`, `+0x28`, `+0x48`, `+0x68`, `+0x70`. Without an
effect the date is 0, and the writer returns `0x136`. Negative rates are not scaled, and `new_i` can keep a negative rate.

### Dates are chrono dates

The date is a packed chrono `NaiveDate`, not a day counter:

- `0x1450810` panics with `` `NaiveDate + TimeDelta` overflowed `` when the add at `0x151f870` returns 0.
- `0x151f870` reads two tables. All 400 flag bytes at `0x2504e5` and all 401 delta bytes at `0x250354` equal values computed here from
  the leap rule and the weekday of 1 January alone (`evidence.json`, `calendar_tables`).
- The cooldown test at `0x3744312` is a signed compare of two packed dates.

So the trial end is a calendar add. Day 352 of 2026 (word `0xfd560a`) + 14 days is day 1 of 2027 (word `0xfd601b`), evaluated on the real helper. A plain integer add would give another word (`date_examples`, 3 rows).

### What is written

The tracker table at `+0xc0` has 0xe8-byte buckets: a 20-byte address, then a value at bucket `+0x18`.

| Value offset | Written here | Read here |
|---|---|---|
| `+0` | 1 | the row reader: non-zero selects the row, otherwise the default row |
| `+8..+0x28` | new rates | the row reader |
| `+0x28` | `v` | the row reader |
| `+0x30..+0x70` | requested and old rates | the row reader, only when the date is non-zero |
| `+0x70` | end date, today + 14 days | the row reader, then gate 2 |
| `+0x78` | old multiplier | the row reader |
| `+0xb0` | never | gate 5, cooldown date |

Each linked user is written first, then the sender; a missing bucket is created by `0x3596da0`, which zeroes `+0xb0`. Linked users get
the same row, and their cooldown date is left alone.

The default row, used when the sender has no bucket or value `+0` is 0, takes the four rates at tracker `+0x48` and constants 0.0, date
0 and multiplier 1.0. The all-0xff and all-0xfe addresses get a zero row with multiplier 0, so only a negative requested rate has an
effect for them.

### Worked examples

The `examples` list in `evidence.json` holds five evaluated calls: a fresh row with a 10% tier and one linked user, rates already met,
a cooldown on day 90 and on day 89, and an end date with no cooldown date.

### Against the reference

`reference-diff.tsv` has 11 rows. `l1/exchange/handlers/55_start_fee_trial.rs` has the right order of gates and the right rate
formula. Its largest errors are the date type and the single `trial_end_day`: the writer stores `+0x70` and the cooldown reads `+0xb0`,
which this path never writes.

## Implementation and comparison

not yet implemented. `tools/fees_start_trial.py` holds a closed-form model of one call for comparison only; it is not recovered Rust.

## Results and limitations

- 2692 vectors, 0 mismatches against the model. Outcomes: 0x134 56, 0x135 174, 0x136 175, 0x137 174, 0x138 47, 0x143 17, 0x186 1989, 0x187 4, 0x77 4, 0x9d 4, 0xab 10, panic 38.
- Instructions executed: 1023 of 1055. Not executed: 1 padding and the two ranges in `unexecuted`, which are in the library
  date helper. Every instruction of the subject functions ran except that padding.
- 284 mutants of conditionals, displacements, immediates, predicates and SSE operations: 278 killed, 6 equivalent with
  reasons in `mutations.tsv`. The first survey left survivors that exposed two comparison gaps: error payloads were checked at one word
  only, and the parser stub ignored the string length. Both are closed.
- 63 unit tests, with negative controls for the digest, decoder, FDE bound, pinned bytes, calendar tables and wrong expectations.

Inferences, kept apart from the above:

- Byte 3 at exchange `+0x8f2` means mainnet: status `0x8d` reads "Action only allowed on testnet". If so, this action is rejected on
  mainnet in #94, and the writer runs on other chains only. No chain value is proved here.
- `v` is a volume word, as the reference says, because tier thresholds are compared with it. Its writer was not traced.
- Value `+0x70` is an `Option<NaiveDate>` niche over `requested`, `old` and the date, because the reader copies those words only when it
  is non-zero and a packed date is never 0.
- The multiplier is copied unchanged here. Its use was not traced.

Unresolved:

- Who clears value `+0x70` when a trial ends, and who writes `+0xb0`. A row with a date stays active for gate 2 until that happens. The
  rollover family `0x26ff460`, `0x4ce8b40`, `0x4ce9670` is the lead, and it belongs to an open packet, so it is not read here.
- Which entry path reaches each of the three handler bodies.
- The last two words of a template row (`+0x20`, `+0x28`) are not read on this path.
- The decimal parser and conversion are stubs, so rate text rules are not fixed here.
- NaN cases are evaluated, but whether a NaN can reach this path is not shown, because the conversion is a stub.
