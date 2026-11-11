# exchange: spot-deploy perp-to-spot charge path of node #115 (impl_spot_deploy.rs)

With this packet the whole charge decision of the spot-deploy perp-USDC-to-spot conversion can be re-implemented from
bytes: which user and quantity are looked up, when the request is refused with "could not convert perp usdc to spot",
how the fee is rounded up to whole units, when the ledger row is marked and when the two debit helpers and the event
are reached, together with every failure exit and its source Location, in three 2.4 KB bodies and five of their
callees, each checked against an independent Python specification (42,000 cases, 75 negative controls, all detected).

- Component ID: `exchange` (`l1/src/exchange/impl_spot_deploy.rs`), supporting `l1-shared` Locations
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `origin/main` at `0781ce048`; no reference source copied
- Claim status: observation (control flow, constants, offsets, Locations) and inference (names, meaning of stub results)
- Scope included: bodies `0x2c57090`, `0x55cbcc0`, `0x55cc610`; quantity lookups `0x2891af0`, `0x5a00b00`;
  rate scaler `0x44811d0`; row getter `0x446b3f0`; name builder `0x421b150`.
  Excluded: the decimal parser `0x43099f0`, decimal scaler `0x421e9d0`, counter `0x446bdd0`, fee helper `0x38bc000`,
  debit helpers `0x4482740`/`0x2a82ea0`/`0x54e03e0`, event writer, context reader `0x421dc00` (all stubbed, see below).
  No PROGRESS gate is requested.

## Reproduce

Run from the repository root with the node #115 artifact in place (the binary is never executed):

```
python3 tools/spot_deploy_charge_115.py --out research/work-items/exchange-spot-deploy-charge-115
python3 -m unittest tests.test_spot_deploy_charge_115
sha256sum -c research/work-items/exchange-spot-deploy-charge-115/MANIFEST.sha256
```

The tool checks the SHA-256 first, then reads the ELF with the shared `tools/decimal_scaled_u64.py` reader (section
headers, `.eh_frame_hdr` search table, RELATIVE relocations). It uses no external program and no clock or randomness
beyond seeded `random.Random(<string>)`; two runs into different folders are byte-identical. Peak memory is the 106 MB
image plus a 106 MB patched copy while a byte control runs.

## Evidence

Coordinates are virtual addresses of the `.text` image; call sites are listed as offsets from the body start.

| file | content |
| --- | --- |
| `callees.tsv` | every call site reached by the cases, its offset and the callee address read from the call bytes |
| `locations.tsv` | each panic exit with the Rust `Location` (file, line, column) decoded from the relocated record |
| `outcomes.tsv` | how many cases ended in each outcome per body, lookup copy and leaf helper |
| `controls.tsv` | each negative control, its meaning and the first case where it diverged |
| `measure.json` | case count, control count, detected count, mismatches |

Observed layout of the three bodies (argument registers at entry, `r14` = exchange state):

- `rcx` is the index of the user table entry; `[state+0xa0]` is the table length, `[state+0x98]` its 32-byte entries
  whose first word is the token key; `[state+0xb8]`/`[state+0xb0]` are the token rows (stride `0x158`, decimals byte at `+0x48`).
- Order of events: bounds check, parse of two strings (`0x43099f0`), quantity lookup, second bounds check, token
  bounds check, scale of the second parsed value with mode 1 and the token decimals, counter-handle presence check,
  counter read, refusal above `0x68db8bac710cb`, fee slot bounds check, fee helper, token bounds check, ledger update,
  early success when the charge is zero, then two debit helpers, a 20-byte address copy, optional context read when
  `[state] == 1`, and the event with amount `-charge / 1e6`.
- The bodies `0x2c57090` and `0x55cc610` share one state layout; `0x55cbcc0` moves the counter handle to `+0x1340`,
  the fee table to `+0x4b38`, the vector to `+0x1330` and the event base to `+0x7c0` (`LAYOUT_B` in the tool).
- Error results are 0x70-byte records. Parse, lookup, fee and second-parse errors are copied unchanged; a scale error
  keeps the payload and gets tag `0xae`; the refusal has tag `0xee`, a pointer into `.rodata` and length `0x23`.
- Decoded panic Locations (see `locations.tsv`): debit failures `impl_spot_deploy.rs:476:18` and `:484:18`,
  index/slot/row bounds in `spot_meta.rs`, `books.rs` and `clearinghouses.rs`, the missing counter handle in
  `clearinghouses.rs:11:29`, the lookup subtraction in `spot_meta.rs:1055:9`, the rate negation in `core/src/num/mod.rs:418:5`.

Exit table of the three charge bodies (call-site offsets are for `0x2c57090`; `0x55cbcc0` and `0x55cc610` are
16 bytes shorter after the first debit call, see `OFFSETS_BC`):

| exit | condition | result | evidence |
| --- | --- | --- | --- |
| `panic_idx0` | `rcx >= [state+0xa0]` | bounds panic, Location `spot_meta.rs:590:25` | call `+0x8bb` |
| parse error | first parse tag is not `0x1a2` | the 0x70-byte record is returned unchanged | copy path at `+0x438` |
| lookup error | lookup tag is not `0x1a2` | record returned unchanged | copy path at `+0x4a1` |
| second parse error | second parse tag is not `0x1a2` | record returned unchanged | copy path at `+0x525` |
| `panic_idx1` | index re-check against `[state+0xa0]` fails | bounds panic | call `+0x8cb` |
| `panic_key` | token key `>= [state+0xb8]` | bounds panic, `spot_meta.rs:119:33` | call `+0x77e` |
| scale error | scale tag is not `0x1a2` | drop helper, same record with tag `0xae` | call `+0x5fb`, `+0x668` |
| `panic_none` | counter handle `[state+0x7d0] == 0` | `Option` panic, `clearinghouses.rs:11:29` | call `+0x8f7` |
| refusal | counter `> 0x68db8bac710cb` | tag `0xee`, text of 35 bytes | `+0x676` |
| `panic_slot` | index `>= [state+0x3ae8]` | bounds panic, `books.rs:19:47` | call `+0x78b` |
| fee error | fee tag is not `0x1a2` | record returned unchanged | copy path at `+0x693` |
| `panic_row` | token key `>= [state+0xb8]` after the fee call | bounds panic | call `+0x798` |
| zero charge | `ceil(fee / 100) == 0` | ledger updated, tag `0x1a2`, no debit | `+0x2d0` branch |
| `panic_debit1` | first debit tag is not `0x1a2` | `Result::unwrap` panic, `impl_spot_deploy.rs:476:18` | call `+0x81e` |
| `panic_debit2` | second debit tag is not `0x1a2` | `Result::unwrap` panic, `impl_spot_deploy.rs:484:18` | call `+0x8a9` |
| success | otherwise | tag `0x1a2` after the event call | call `+0x767` |

The ledger update is the same for every non-panic exit that follows the fee call: if the first byte of the token row
is zero the row is set to `(1, charge)`; a non-zero byte keeps the row as it was.

Callee findings that the tool proves on bytes:

- `0x2891af0` / `0x5a00b00` (two identical copies): bounds-check the entry index, read two token keys from the entry
  (second word first), subtract the decimals bytes (`+0x49` of the second minus `+0x48` of the first, panic on borrow),
  call the scaler with mode 2 and that difference, map a zero result to tag `0xad` and an error to the same record
  retagged `0xad`.
- `0x44811d0`: values above `0x028f5c28f5c28f5c` pass through; otherwise the value is converted as a signed 64-bit
  integer, multiplied by the double at `+0x4e0`, mapped to 0.0 when infinite or NaN, clamped to +/-2^63, converted with
  saturation, negated (panic for `i64::MIN`), clamped to `0x0147ae147ae147ae` and floored at zero.
- `0x446b3f0`: row `idx` of a table with stride `0x510`, panic when `idx >= len`.
- `0x421b150`: allocates 4 bytes holding the ASCII text `USDC` and returns a 4/4 capacity/length string.
- The remainder test inside the bodies is the divisibility-by-100 trick (`x * 0x8f5c28f5c28f5c29` rotated right by 2
  compared with `0x028f5c28f5c28f5c`); the largest multiple of 100 below 2^64 (`2^64-16`) is the only value where the
  comparison is exactly equal, and the case generator includes it.

## Implementation and comparison

`tools/spot_deploy_charge_115.py` runs each function from its own bytes in the shared evaluator (extended inside the
tool by `ror`, `pcmpeqd`, `cvtsi2sd`, `divsd`, `movsd`, `mulsd`, `ucomisd`, `maxsd`, `minsd`, `cvttsd2si`, `movq` and
`cmovnp`). Every call is a stub keyed by its call-site offset: the stub records its arguments (registers and the memory
they point to) and returns the result stored in the case. `spec()`, `lookup_spec()`, `rate_spec()`, `rowget_spec()` and
`usdc_spec()` are separate Python functions written from the listing; they predict the outcome, the whole ordered call
trace and the final ledger row. A case passes only when outcome, trace and row all agree; panics must also name the same
exit and decode to a Location.

| part | cases | result |
| --- | --- | --- |
| charge bodies A, B, C | 6,000 each | 0 mismatches |
| quantity lookups (two copies) | 6,000 each | 0 mismatches |
| rate scaler, row getter, USDC name | 4,000 each | 0 mismatches |
| total | 42,000 | 0 mismatches |

Case classes cover every exit (bounds, parse errors, lookup error, scale error, missing handle, refusal at and above the
limit, fee slot, fee error, row panic injected by a stub that shrinks the token table, both debit failures, zero charge,
set and unset ledger flag, both context modes) and edge fees (`0`, `1`, `99`, `100`, `101`, `2^64-16`, `2^64-1`, ...).

Negative controls (75, all detected, listed in `controls.tsv`): 18 wrong specifications for the bodies, 27 single-byte
patches of the three bodies (constants, branch directions, tags, strides, offsets), 5 wrong lookup specifications and 5
lookup patches, 5 wrong leaf specifications and 8 leaf patches, and 7 out-of-range inputs (flipped digest byte,
address inside a function used as a start, unknown call site, unwritten stub read, non-Location address, rotate by
zero, 65-bit value). The `seta` control survives until the case with fee `2^64-15`.

## Results and limitations

Metrics: 42,000 comparison cases, 0 mismatches, 75 negative controls, 75 detected (`measure.json`).
Limits, stated plainly:

- The stubbed callees (decimal parser, decimal scaler `0x421e9d0`, counter, fee helper, debit helpers, event writer,
  context reader, allocation, vector helper, drops) are not reconstructed here; their result records are random bytes with
  a controlled tag, so the packet proves what the bodies do with the answers, not what the helpers compute.
- Panic exits are checked by call-site name and decoded Location; the panic message arguments are not compared.
- The row-panic exit (`panic_row`) is unreachable with consistent memory and is reached only through a stub that shrinks
  `[state+0xb8]`; likewise `panic_idx1` needs a parse stub that shrinks `[state+0xa0]`. These are recorded as defensive
  re-checks.
- The meaning names (charge, counter, ledger) are inferences from the arithmetic; the bytes fix only the operations.
- No gate is requested. Static analysis only; the node was never run.

Next question: reconstruct the decimal scaler `0x421e9d0` (power-of-ten table by bit tests, overflow to tag `0xac`,
the three rounding modes through the decimal library) and the counter reader `0x446bdd0`, which feed this path.
