# RE-007: reconstruct the node #115 BOLE interest index writer 0x36a0200 and prove it on 11,636 byte-level cases

This packet lets a reconstruction write the BOLE token row interest update as an exact integer function: given a 0xb8-byte token row, a block time and a reserve share, the writer at `0x36a0200` either leaves the row untouched (any failed guard) or stamps the new time, grows the borrow and supply interest indices over the elapsed milliseconds of a 365.25-day year, adds the reserve fee to the pending word, and settles pending against balance into paid, with saturating adds that report through one shared overflow-log Location. The independent specification in `tools/bole_index_writer_115.py` agrees with the real #115 instruction bytes, stepped by a Python evaluator, on all 11,636 cases (0 mismatches), and the comparison is shown to be able to fail by 166 negative controls that are all detected.

- Component ID: RE-007 (risk, oracles and liquidation; BOLE token refresh path). The writer is reached from the token refresh body `0x369a480`; the packet does not claim the refresh body, the liquidation step or any state-root gate.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`).
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was consulted or copied. The deleted release-94 packet `RE-007-bole-liquidation-step-94` (repository history before `8fd8db680`) was used only as a lead for the row field offsets and the shape of the model; every address, offset, constant and behaviour below was re-derived from #115 bytes, and the specification is the arbiter, not that packet.
- Claim status: bytes, relocations, FDE extents, decoded operands and the case results are observations; the field names (borrow, supply, indices, rate curve, reserve share) and the economic reading are inferences from arithmetic shape; no captured node was run and no dynamic behaviour is claimed.
- Scope included and excluded: the single function `0x36a0200..0x36a08ad` (1,709 bytes, 439 decoded instructions), its 13 wide-divide call sites and 2 overflow-log call sites, and the one call edge from the refresh body. Excluded: the refresh body `0x369a480` (its token container is a ring of 0xb8-byte rows, not the tree the release-94 packet modelled), the block-step host that inlines the bucket gate and step body, the system-user pass, the sweeps, and every state-root or checkpoint gate. No component gate is requested.

## Reproduce

From the repository root with the authenticated `artifacts/node/115/hl-node` present:

```sh
python3 tools/bole_index_writer_115.py --out research/work-items/RE-007-bole-index-writer-115
python3 -m unittest tests.test_bole_index_writer_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
mkdir -p work/re007-index-check
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/bole_index_writer_115.py --out work/re007-index-check/one
PYTHONHASHSEED=271828 TZ=Pacific/Honolulu python3 tools/bole_index_writer_115.py --out work/re007-index-check/two
diff -r work/re007-index-check/one work/re007-index-check/two
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-007-bole-index-writer-115 work/re007-index-check/one
(cd research/work-items/RE-007-bole-index-writer-115 && sha256sum -c MANIFEST.sha256)
```

Use empty output directories. The tool authenticates the whole input binary by SHA-256 before parsing, reads the ELF only through `tools/elf_index.py` and `tools/fde_extents.py` (SHT_NOBITS sections never resolve an address), never executes the binary and calls no external program. A run takes about 40 seconds and about 410 MB of resident memory (Python 3.12.3, Linux x86-64); the unit tests take about 13 seconds. GNU objdump was used for human inspection only; its text is neither parsed nor stored. Every number below is read from `evidence.json`, `measure.json` or the TSV files.

| File | Content |
| --- | --- |
| `evidence.json` | function extent and hash, indirect call sites with relocated targets, overflow-log Locations, 1e14 and year-length immediates, row offsets used, caller boundary, case and control totals |
| `cases-sample.tsv` | all 63 hand-written cases and every 100th generated case, with real-byte results and whether the specification agrees |
| `accrual-samples.tsv` | real runs over one day at eleven pool uses and three reserve shares |
| `controls.tsv` | 25 flawed specifications and 10 input corruptions with the case that caught each |
| `mutations.tsv` | every single-bit byte mutant of a branch, set/cmov, immediate or offset, with result, killer and reason |
| `measure.json` | `cases`, `negative_controls`, `negative_detected` and the survivor count not counted |

## Evidence

All addresses are linked ELF virtual addresses. The FDE `0x36a0200..0x36a08ad` covers 1,709 bytes whose SHA-256 is recorded in `evidence.json`; the decoder walks it linearly and ends exactly on the FDE end. 436 of the 439 instructions are stepped by at least one case; none of the single-bit mutants of the function is unreached.

- **Callers.** One edge was verified from bytes: inside the refresh body `0x369a480`, a call through the data slot `0x64e7828` at `0x369a69f`; a relative relocation points that slot at `0x36a0200`. The slot call passes the row pointer, the time pointer and the reserve share in `rdi`, `rsi`, `rdx`. No direct `call` reaches the function.
- **Wide divide.** 13 sites call slot `0x64dfaf8`, relocated to `0x63efec0`, with `rdi:rsi` as a 128-bit dividend and `rdx:rcx` as the divisor; the harness models it with exact integers and counts 92,059 divides over the full run. The divisors are the immediate `0x5af3107a4000` (1e14) and the year length `31557600000` ms (365.25 days), both read from `movabs` immediates (sites in `evidence.json`).
- **Overflow log.** Two sites (`0x36a07ce`, `0x36a088f`) call slot `0x64e4ea8`, relocated to `0x4524e40`, after a RIP-relative `lea rsi` of one Location record `0x6487460`, which decodes to `l1/src/qtys/mod.rs:835:1`. Both the pending add and the paid add therefore report through the same record; the log is followed by a saturating select (`cmovae` with all ones), so the stored word is `0xffffffffffffffff` after a logged overflow. The 261 logs in the run split into one per saturation.
- **Row layout used.** `+0x10 px` (untouched), `+0x18 balance`, `+0x20 paid`, `+0x28 pending`, `+0x30 low`, `+0x38 high` (untouched), `+0x40 a` (borrowed), `+0x58 ia` (borrow index), `+0x60 b` (supplied), `+0x78 ib` (supply index), `+0x80 min`, `+0x88 max`, `+0x90 bend`, `+0x98 k` (rate curve), `+0xa0` time words (date, seconds, nanoseconds). The displacement census in `evidence.json` shows exactly these words used plus the stack-held copies.
- **Time.** The date word is `year << 13 | ordinal << 4 | 2`; the writer converts it to Unix milliseconds with calendar division magic constants valid for the full signed 19-bit year range; years below 1 are lifted by 400-year cycles; the clock is clamped at zero; sub-millisecond nanoseconds are dropped by flooring.

### Reconstructed behaviour

1. If the row time words equal the block time words exactly, only the settle step runs: `moved = min(pending, balance)`, `balance -= moved`, `pending -= moved`, `paid += moved` (saturating, logged).
2. Otherwise `borrowed = ceil(a * ia / 1e14)` and `supplied = floor(b * ib / 1e14)`; a high word of `b * ib` at or above 1e14 returns untouched, as does `borrowed >= 2^64`.
3. Use `u = floor(borrowed * 1e14 / supplied)` (0 when nothing is supplied), exit if `u >= 2^64`, then `u = min(u, 1e14)`.
4. The rate is the two-arm curve over `min`, `bend`, `max` with the kink at `k`: `bend` at `u == k`; below it `min + bend-min` scaled by `u*1e14/k`; above it `bend + (max-bend)` scaled by `(u-k)*1e14/(1e14-k)`; every failed guard (`bend < min`, a ratio of 2^64 or more, a scaled guard) falls back to the arm's anchor rate.
5. `elapsed = now_ms - row_ms` must be non-negative and at most 31,557,600,000 ms (inclusive); `grown = scaled(elapsed * rate / year, ia)`.
6. `share = floor(a * 1e14 / b)` (0 when `b == 0`; 2^64 or more returns untouched), `supply = scaled(grown, share)`, `fee = scaled(supply, keep)`, `tokens = scaled(fee, b)`; `fee > supply` returns untouched.
7. The new indices are `ia + grown` and `ib + (supply - fee)`; a carry out of either returns untouched. Then the row time is stamped, `pending += tokens` (saturating, logged), and the settle step of rule 1 runs.

Here `scaled(x, f)` is `x * f / 1e14` with the high-word guard of rule 2 (the product's high 64 bits must be at most 1e14 - 1).

### Findings against the release-94 lead

The bytes at `0x36a0200` reproduce the release-94 model case for case (all 60 hand cases carried over from that packet agree with the specification and the bytes; 3 further hand cases were added here). Three #115 coordinates differ and are re-established here: the function and its three slots moved; the two overflow reports share one Location record (`l1/src/qtys/mod.rs:835:1`); and the caller no longer reaches the writer through a tree-walking token loop, but through the slot call `0x369a69f` in a refresh body whose row address arithmetic multiplies by `0xb8` over words at `[rdi+0x58]`..`[rdi+0x78]` (a ring-like walk with a call to `0x4506810` per row), not the B-tree walk the release-94 harness built. That ring layout is why the release-94 harness for the whole refresh cannot be reused unchanged and is left open.

## Implementation and comparison

`tools/bole_index_writer_115.py` has three independent layers.

1. **Evaluator** (the shared decoder/machine written for earlier packets, about 890 lines): decodes the 439 instructions, executes registers, flags, memory and the integer subset used here, models only the two slot targets (`0x63efec0`, `0x4524e40`) as hooks, poisons unset registers and memory, and halts on any unmodelled call, unmapped read or step-limit overrun.
2. **Specification** (`accrue_spec`, `rate_of`, `scaled`, `settle`, `unix_millis`): Python integers only, no instruction semantics; it also takes an optional `flaw` name used only by the controls.
3. **Cases**: 63 hand cases (each guard, each saturation, the year boundary inclusive and one millisecond over, clocks before the epoch and years below 1, the 2^64 index edges), 1,373 calendar cases that sweep the year word from -401 to 262,143 for both the row time and the clock, and 10,200 deterministic xorshift cases in four profiles (ordinary pools, edge words, large words and mixed). 11,636 cases in total; each is run once on the bytes and once on the specification and compared on all fourteen row words, the three time words and the number of overflow logs.

Negative controls (all must be detected, otherwise the tool fails; `measure.json` records `negative_controls` = 166 and `negative_detected` = 166):

- 25 flawed specifications (floor instead of ceil, ceil instead of floor, missing use cap, 365-day year, inclusive year, each of the seven guards removed, wrapping instead of saturating pending and paid, missing logs, swapped indices, wrong token base, no low arm, bend equal to low, and so on), each shown to disagree with the real bytes on at least one of the first 1,600 cases;
- 10 input corruptions: a flipped input byte changes the digest, a truncated image, an address inside the function, an address outside every section, an address before the function, a zero divisor reaching the wide divide, the divide hook removed, the log hook removed, a 20-step limit, and the two hooks swapped;
- 131 single-bit byte mutants of branches, flag-sets, conditional moves, immediates and displacements that the case run kills (`mutations.tsv`).

Another 24 mutants survive and are **not** counted as controls: 10 are bit 0 of calendar division magic constants (the case run leaves every quotient of a 19-bit year word unchanged), 8 are 1e14 divisor or high-word edge immediates (a changed result needs a quotient of at least 1e14 or a high word of exactly 1e14 - 1, which no case builds), and 6 are a flag byte, an all-ones saturation selector, two immediates of 1, a compare against 0 and a compare against 2 for which no reason is claimed. Not claiming a reason is deliberate.

## Results and limitations

- 11,636 cases, 0 mismatches; 92,059 wide divides and 261 overflow logs exercised; 436 of 439 instructions stepped; 131 killed and 24 surviving byte mutants (155 single-bit mutants in all, 0 unreached); 25 of 25 flawed specifications and 10 of 10 input corruptions detected; 23 unit tests, no skips; 2 identical regenerations under different hash seeds and time zones.
- The model covers the writer only for the row, time and reserve-share words it receives. It says nothing about how the refresh body chooses prices, about the order of tokens, about the other two copies of the block step, or about whether the reserve share is `1e14`-scaled by every caller.
- The 24 survivors above are the honest limit of the case set: a reconstruction that reproduces the kink-arm anchors and the saturating logs is covered, but one that changes a 1e14 divisor in the third decimal digit of a billion-scale quotient would not be caught here.
- The field names are inferences. The Location `l1/src/qtys/mod.rs:835:1` suggests a shared saturating quantity add; that source mapping is a hypothesis, not a recovered line.
- No gate is requested. The packet is a bounded function-level reconstruction with a byte-level check, not a claim about the whole BOLE module.

Next question: the refresh body `0x369a480` now has a known callee. Its ring iterator `0x4506810`, its price scale `0x369f730` (three call sites), and the median helper decide which tokens reach the writer and with which `keep`; recover them with the same method, starting from the ring layout above.
