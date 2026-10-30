# RE-004: which orders does node #94 admit as priority orders, and what does the priority word change?

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, outcomes, weight table and id table; inference for "priority", "IOC", "delay" and "perp", which come from error text and shape; unresolved items are listed under limits
- Scope included and excluded: included is `0x3978840` and how its 10 call sites form the priority argument. Stubbed as edges are four tree helpers: `0x33b68a0`, `0x3bb3340`, `0x33987c0`, `0x33b6170`. Excluded are the balance test after this gate, the builder of the element tree, and the users of the returned delay.

## Reproduce

Working directory is the repository root. Platform Linux x86-64, Python 3.12.3, standard library only. The binary is read as bytes and never run. No external program is called, so the binutils version cannot change a result.

```
python3 tools/artifacts.py verify
python3 tools/priority_admission.py --out research/work-items/RE-004-priority-admission-94
python3 -m unittest tests.test_priority_admission
```

The tool refuses any input whose SHA-256 differs. It uses `tools/elf_index.py` for sections and `tools/fde_extents.py` for FDE records. Output is byte-identical between runs.

## Evidence

Addresses are virtual addresses. `.text` VA minus file offset is 0x1000; `.rodata` VA equals file offset.

### Boundaries and callers

FDE `0x3978840..0x3978f3d`, 1789 bytes. The evaluator covers the body up to `0x3978ec6`; the rest is unwind cleanup. There is no second copy: an earlier tag census also hit `0x4b24300`, but that function is unrelated and has a different size.

The function has 10 direct call sites (`callers.tsv`). Fixed bytes before each call show how `esi` is made:

| Form | Sites | Meaning |
| --- | --- | --- |
| `xor esi,esi; cmp reg,3; cmove esi,...` | 6 | esi is the word at `+0x44` when the word at `+0x40` is 3, else 0 |
| `cmpl $3,0x40(%rsi); mov 0x44(%rsi),%ebp` | 1 | the same, spelled out |
| `xor esi,esi` | 3 | always 0 |

Each of the 6 order handlers in `handler-guards.tsv` also holds one compare with `0x5f5e101`, which leads to tag 0xb2, and one write of tag 0xb4. So in those handlers the word is at most 1e8.

### Inputs

`rdi` is the result, `esi` the u32 word p, `rdx` an owning B-tree, `rcx` three f64 values a, b, d at `+0`, `+8`, `+0x10`. Tree elements are 0x18 bytes at node `+8`: id u32 at `+0`, byte F at `+8`, byte T at `+0x11`. Node: parent at `+0`, parent index at `+0x110`, length at `+0x112`, edges at `+0x118`.

### p != 0

Elements are walked in key order, inline, and the first failure ends the walk. For each:

1. id above 99999999, or id in `10000..=109999`: tag 0xb5.
2. T != 2, or F != 1: tag 0xb3.

An empty tree passes. Then:

3. `w = ((p as f64) / -1e8) / d + 1.0`. Note the negative divisor constant at `0x20aea0`.
4. `w` must pass the bit test at `+0x495`: NaN, either infinity, any negative value and any value above 1.0 give tag 0xb2. `-0.0` passes.
5. `b < a` or a NaN: assertion `self.0 >= other.0`, `base/src/duration.rs:101:13`.
6. `b - a` is NaN: assertion `self.0 >= 0.`, `base/src/duration.rs:124:13`.
7. Result tag 0x186 with f64 `a + w * (b - a)`.

So `p = 0` would give b, and `p = d * 1e8` gives a, in a straight line. Above that, w is negative and tag 0xb2 follows. A zero d gives tag 0xb2 for every p >= 1, because w is negative infinity. A negative d gives w above 1 and the same tag, unless |d| is so large that the sum rounds to exactly 1.0. An infinite d gives w = 1.

`priority-edges.tsv` gives the last admitted word from real bytes: 100000000 at d = 1.0, 25000000 at d = 0.25, 100000 at d = 0.001. At d = 100.0 all words up to `u32::MAX` pass this gate, so the 1e8 compare in the handlers is then the only limit.

`examples.tsv` has real byte results with a = 0.25, b = 2.0, d = 0.1: the plain path gives 2.0, word 1000000 gives 1.825, 5000000 gives 1.125, 10000000 gives 0.25, 10000001 gives tag 0xb2.

### p == 0

No error is possible. Elements are walked through `0x33b68a0`:

- T == 3 ends the walk. Inference: this byte value is the None niche of the iterator item, not a real element.
- T == 2 and F == 0: skipped.
- id in `10000..=109999` or at least 1e8: inserted in the first set. Otherwise in the second set.

Result tag 0x186 with f64 b when the second set is not empty, else 0.0. Both sets are in the result, at `+0x10` and `+0x28`.

### Whole-domain tables

`weight-classes.tsv` is the test of step 4 over all 2^64 f64 patterns, in 9 classes. Only two classes pass: `0.0..=1.0` and `-0.0`. `asset-classes.tsv` is the id rule over all 2^32 words, in 4 pieces.

### Error text

| Tag | Text |
| --- | --- |
| 0xb2 | Invalid priority |
| 0xb3 | Priority order must be IOC |
| 0xb4 | Insufficient delegatable balance for priority order |
| 0xb5 | Invalid asset for priority order |

### Inferences

These are readings of the observations above, not observations.

- p is a priority level in units of 1e-8, from tag 0xb2 and the `+0x40 == 3` selection. The word 3 is a variant of an order grouping field, from its place beside the order list at `+0x30`, `+0x38`.
- T == 2 is IOC, from tag 0xb3. F is unnamed; priority orders need it to be 1, and plain IOC orders with F == 0 are skipped.
- a and b are `Duration` values in seconds, from the two assertion texts and the path `base/src/duration.rs`. The result is a delay: b is the full delay and a the shortest, which a level of d reaches.
- Ids in the second set and admitted for priority are perps: `0..=9999` and `110000..=99999999` match the ranges of open `RE-004-wire-asset-codec-94`.
- The merged `RE-004-wei-buffered-cap-94` asks what state supplies its u32 factor. At `0x1ea3c33` handler `0x1ea3140` loads this same word into `r8d` for the call at `0x1ea3c38`, and the next compare leads to tag 0xb4. That was read by eye and is not in the generated files.

The reference has no text for this: `rg -i "priority order|invalid priority|delegatable" references/can1357-hl/l1` finds nothing. Its `l1/action_delayer.rs` holds constants 10000, 110000 and 1e8 under other names, and a delay type, so that file is the lead for what the delay feeds.

## Implementation and comparison

Not yet implemented in Rust. The comparison is real bytes against a specification written from the claim.

Real instructions run in a Python evaluator, including the inline tree walk over fake nodes of height 0, 1 and 2. Four helpers are stubbed. The stubs are not free: each one checks the nine words of the owning tree iterator it is passed, and each run checks that the tree was consumed on every path that must consume it. Set inserts are recorded in order as a running hash. Assertion stubs check the text pointer and length against the two strings in the file. Error results must write only the tag.

| Check | Count | Result |
| --- | --- | --- |
| Named cases | 57 | 0 mismatches |
| Fixed-seed random cases | 5000 | 0 mismatches |
| Weight test, all 2^64 f64 patterns | 9 classes, 1554 runs | closed form holds |
| Id rule, all 2^32 words | 4 pieces, 258 real runs each for each path | closed form holds |
| Priority edge | 6 values of d, 34 real runs each where bisected | see `priority-edges.tsv` |
| Mutations of reached conditions and immediates, plus 2 constants | 100 | 98 killed, 2 survive |

Why the table rows are proofs: each weight class is one outcome of every bit test and of the one compare with 1.0, and the end points and 256 interior points run on real bytes. The element id is loaded once and read by two compares in the priority walk, pinned by `asset_compares`. So its outcome is constant between the three cut points, and the ends of each piece decide it. The plain path reads the same three constants (read by eye; the ends and 256 interior points of each piece ran on real bytes). For a fixed d > 0, w falls as p rises and one test reads it, so one edge decides all words.

The 2 survivors compare the height with 8 to enter the unrolled descent; no tree here is that tall. `evidence.json` lists 16 directions not covered and why, 12 of them the same tall-tree rows. A change to either list fails the tool.

## Results and limitations

- Trees of height 8 or more were not run. The rows they enter are pointer walks only.
- The four tree helpers are stubbed. That they do what their names here suggest is an inference from their callers' use.
- The specification treats `a`, `b`, `d` as any f64. Real values are not known. `d` and the triple come from state at `+0x3660` in the handlers, and nothing here says what sets it.
- Whether the plain path's second-set test gives the delay used by the callers was not traced. The six handlers read here drop both sets after the call.
- The source of bytes T and F in an order was not traced.
- Requests no progress gate.

Next question: what sets the triple at state `+0x3660`, and which caller uses the returned delay?
