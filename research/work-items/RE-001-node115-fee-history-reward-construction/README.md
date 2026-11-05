# RE-001: node #115 fee-history reward-row construction

The fee-history percentile code consumes a vector of reward/gas pairs. Earlier
work left construction of those inputs opaque. This packet recovers the composed
constructor: paired row truncation, a 128-bit fee floor and cap, and checked
differences of cumulative gas. It is static preparatory research, with no change
to the node's fee policy or claim of a source-built implementation.

- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: node #115, Linux x86-64, `artifacts/node/115/hl-node`, 105,896,032 bytes.
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; exclusive function ends.
- Denominator: four complete FDE bodies, 9,671 bytes. The large enclosing future
  and the nested receipt-log clone are retained as context, not new ownership of
  all their behavior. Every component acceptance gate remains false.

## Construction contract

The call at `0x2a20e11` in the fee-history future `0x2a1fd20` invokes
`0x2355610..0x23558f1`. The caller supplies two ranges: transaction rows at
336-byte stride and cloned receipt rows at 40-byte stride. Its iterator end is
the **minimum** of their counts, its initial index is zero, and its initial
previous cumulative value is zero. It passes a pointer to a zero-extended
64-bit base fee; an absent optional base fee supplies zero.

The preceding clone at `0x234ae90` preserves each receipt's qword at offset
24 across its deep-clone call. That qword is therefore the constructor's
cumulative input, not a field taken from the cloned log payload. Receipt-log
cloning internals and allocation failure behavior remain dependency boundaries.

For each consumed transaction row, define these raw unsigned fields:

| Name in this packet | Row offset | Width |
| --- | ---: | ---: |
| `prefix` | `0x00` | 128 bits |
| `zero_cap` | `0x40` | 128 bits |
| `other_cap` | `0x50` | 128 bits |
| `priority_cap` | `0x60` | 128 bits |

The observed rule, using mathematical unsigned values, is:

```text
cap = zero_cap if prefix == 0 else other_cap
difference = max(cap - base_fee, 0)
reward = difference if prefix < 2 else min(difference, priority_cap)
gas = current_cumulative - previous_cumulative  # checked u64 subtraction
previous_cumulative = current_cumulative
```

Both the first-row and subsequent-row paths implement the same reward rule.
The prefix comparison is **unsigned 128-bit**, not just the low byte or qword.
The base fee is 64-bit but the fee subtraction and minimum preserve both limbs.
For example, a selected cap of `2^64 + 4`, base fee 5 and uncapped prefix produces
`2^64 - 1`, rather than wrapping the low qword and losing the borrow. A selected
cap below the base fee produces zero. Prefix two or greater applies the second
cap even when it is zero.

These are raw layout labels. This packet does not assign Ethereum transaction
variant names to prefix values or assert that every synthetic 128-bit prefix is
a reachable enum state. Fee-history context and the source Location
`z_forks/reth-rpc-eth-types/src/fee_history.rs:34` support the reward/gas
interpretation; exact original type definitions and units are not recovered.

The receipt's current cumulative qword is at offset 24. The first row subtracts
the supplied previous value; subsequent rows subtract the preceding consumed
cumulative value. Underflow in either path reaches the same panic Location.
There is no successful partial-vector return on that path. The panic runtime,
unwinding cleanup and process-level recovery are outside the claim. In the
recorded caller, previous starts at zero, so the first gas amount equals the
first cumulative amount. A zero difference is accepted.

Output records have stride 32: the reward occupies offsets 0 and 8, and the
gas qword occupies offset 16. The last eight bytes are padding in the observed
stores; no initialized value is claimed for them. Input order is preserved.
Sorting and percentile selection happen later and are credited prior work.
Unpaired tail rows are not consumed by the reward-row constructor. The preceding
receipt clone traverses its full supplied range and may inspect those extra
receipts or fail while cloning them; the synthetic unconsumed-tail checks do
not cover cloning. Empty or exhausted reward iterators return the
observed vector descriptor `(capacity=0, pointer=0x10, length=0)`.

## Evidence and validation

`verify.py` authenticates the whole target image, complete unwind extents,
instruction bytes, native exports, direct/relocated calls, source Locations,
incoming relocation sites and the 22 spans in `obligations.json`. Both GNU and
LLVM disassemblies retain complete function bodies. `records.json` records
unresolved dependencies explicitly. Corruption controls bypass the outer digest
where appropriate so that deeper guards must independently reject changed
instructions, relocations, data and unwind evidence.

`relations.py` derives offsets, strides, prefix thresholds and branch conditions
from actual decoded operands. A limb-based subtraction/comparison relation is
checked against a separately expressed arbitrary-precision integer oracle over
boundary cases and deterministically randomized 128-bit values. Both copies of
the native reward rule are checked. Vector cases cover empty inputs, unequal
counts, nonzero starting indices, repeated cumulative values, maximal u64 gas
and decreasing inputs, including an unconsumed decreasing tail.

Four changed-evidence controls must alter the derived result: cap-field offset,
prefix threshold, fee-floor branch polarity and receipt cumulative offset.
The fixtures are synthetic and the models are independently authored. They do
not execute or emulate the captured code and do not establish native execution
equivalence.

```sh
python3 research/work-items/RE-001-node115-fee-history-reward-construction/verify.py
python3 research/work-items/RE-001-node115-fee-history-reward-construction/relations.py
python3 -m unittest discover -s tests -p test_node115_fee_history_reward_construction.py -v
make doctor
make verify test catalogue-check reproduce
```

Observed commands, results and tool versions are retained in `validation.json`
and logs. No hosted CI, target execution, allocator equivalence or complete
fee-history recovery is claimed.

## Prior work and scope

GPT-6.1 Terra compared all visible open and closed PRs and retained historical
exclusions. The census and assessment are recorded in `pr-census.json.bz2`,
`scope-audit.json` and `overlap-summary.md`. Missing API patches and unavailable
historical records prevent an absolute uniqueness guarantee.

- [#2129](https://github.com/lalalune/hyperliquid-source/pull/2129) owns the
  surrounding future and percentile cursor, explicitly leaving these constructor
  outputs opaque. Its caller body is retained as context here.
- [#355](https://github.com/lalalune/hyperliquid-source/pull/355) covers older
  percentile request comparisons; [#3205](https://github.com/lalalune/hyperliquid-source/pull/3205)
  covers the small-input ordering path for already constructed #115 rows.
- [#1745](https://github.com/lalalune/hyperliquid-source/pull/1745) already
  documents cumulative-gas subtraction and underflow in a different older
  receipt builder. That shared primitive is credited, not claimed as novel.
- [#1700](https://github.com/lalalune/hyperliquid-source/pull/1700) covers blob
  pricing, while [#2005](https://github.com/lalalune/hyperliquid-source/pull/2005)
  covers an older call-request 256-bit cap/tip/base validator with different
  error gates. Neither establishes this zipped 128-bit reward-row construction.

The new question is the composed input contract connecting those paired rows
to the percentile vector. It excludes percentile policy, sorting, transaction
variant naming, complete receipt cloning and generic allocation machinery.

Independent implementation and prose in this packet are MIT-licensed under
the repository license. Captured artifacts retain their original provenance.

The later overlap refresh is retained in `final-overlap-refresh.md`. Previously observed PRs absent from the refreshed listing remain overlap exclusions; unavailable historical contents, missing API patches and later work limit the conclusion.

The full 584-file suite ran on the history-text branch. Each companion branch independently matched the base input hashes and passed its own focused tests and integrity checks; `validation.json` distinguishes reused suite evidence from branch-specific commands. The original base had a stale generated README inventory count; regenerating the catalogue resolves that pre-existing check failure.
