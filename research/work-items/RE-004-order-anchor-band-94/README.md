# RE-004: how far from its reference price can a node #94 order be?

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the float decision, the outcome cap, the tag texts, the vote guard and the serde key; inference for the words "order price" and "reference price" on the two inputs and for the meaning of the classifier values; unresolved items are listed under limits
- Scope included and excluded: included are the gates `0x372f240` (spot) and `0x3713db0` (perp) and the cap helper `0x372b4b0`, which runs as real bytes. The wrapper `0x372efe0` is pinned by its bytes. Stubbed as edges: the classifier `0x3728670`, the exemption test `0x37e4fb0` and the hash `0x399c4a0`. Call sites and the field census are listed as sites. What their enclosing functions do is not claimed here.

## Reproduce

Working directory is the repository root. Platform Linux x86-64, Python 3.12.3, standard library only. The binary is read as bytes and never run. No external program is called, so the binutils version cannot change a result.

```
python3 tools/artifacts.py verify
python3 tools/order_anchor_band.py --out research/work-items/RE-004-order-anchor-band-94
python3 -m unittest tests.test_order_anchor_band
```

The tool refuses any input whose SHA-256 differs. It uses `tools/elf_index.py` for sections and `tools/fde_extents.py` for FDE records. Output is byte-identical between runs.

## Evidence

Addresses are virtual addresses.

### Boundaries and reach

`targets.tsv` gives the FDE of each target: `0x372f240..0x372f3bb`, `0x3713db0..0x3713e93`, `0x372b4b0..0x372b6af`.

Neither gate has a direct call. Each has one pointer slot, `0x5773990` and `0x5773980`. `call-sites.tsv` lists all six calls through them, three per gate. Each call is preceded by one `movq field(%reg),%xmm0`. Four read `+0x3980` and two read `+0x4400`.

Tag census: tag 0x5f is written only at `0x372f34f` and `0x3713e87`. Tag 0xee is written only at `0x372f38e`.

### The field

`vote-guards.tsv` holds three guards with the same byte shape. Each loads f64 0.2 from `0x20a768` and 0.99 from `0x20a6a0`, then `ja` to one error block that writes tag 0x41, then stores the value. Two store to `+0x3980` and one to `+0x4400`. Tag 0x41 prints `Max Order Distance from anchor invalid.`

`serde-keys.tsv`: the reader at `0x275b122` loads `+0x3980` and passes the key `max_order_distance_from_anchor`. `field-census.tsv` lists all 23 byte-shaped uses of the two offsets: 16 of `+0x3980` and 7 of `+0x4400`, 6 of them stores. So the offset differs by layout and the name comes from one reader.

### The decision

Call the inputs `a` (`r8`), `b` (`r9`) and `p` (`xmm0`). Both gates turn `a` and `b` into f64 with the same unsigned sequence. Its low and high 32-bit halves are each exact as doubles, so the final `addsd` gives the nearest double to the u64. The tool pins the instruction sequence and its two rodata constants. Then:

```
r = float(a) / float(b) - 1.0
admitted when p > |r|
else admitted when 1.0 > p and r > 0.0 and 1.0/(1.0 - p) - 1.0 >= r
else tag 0x5f with payload p * 100.0
```

`paths.tsv` is the output of a symbolic walk over the real instructions from the divide to the join. It forks at each branch, and it stops if it meets any instruction it does not model. Both gates give the same five paths, equal to a list written separately in the tool. This covers all `a`, `b` and all 2^64 bit patterns of `p`, NaN included, because each condition is an IEEE compare with the branch's own unordered result.

The payload prints through `Order price cannot be more than {}% away from the reference price` (Display arm `0x3800020`). So `p` is a fraction and the text shows a percentage.

Consequences for `p` in the vote range:

- The side of the order is not an input. The band is `-p < r <= 1/(1-p) - 1`, so a value between `(1-p)b` and `b/(1-p)`. It is symmetric as a ratio, not as a difference: `p = 0.5` admits half to double, `p = 0.99` admits up to about 99 times `b`.
- The lower edge is strict and the upper edge is inclusive. With `b = 100` and `p = 0.5`, 50 is refused, 51 is admitted, 200 is admitted, 201 is refused.
- The first test `p > |r|` decides the lower side. On the upper side it adds nothing once `1/(1-p) - 1 >= p`. The tool asserts that for every `p` in the edge table.
- `b = 0` always fails: `a/0` is infinity and `0/0` is NaN. `p` NaN always fails.
- For `p >= 1`, the only test left is `p > |r|`. This cannot arise from the vote guard's ordered range.

`band-edges.tsv` gives the first and last admitted `a` for 11 values of `b` and 8 of `p`. The tool finds each by binary search on the specification, which is valid because `r` never falls as `a` grows. It then runs the real bytes of both gates at `first-1`, `first`, `last` and `last+1`. Next to each edge is the real-number edge computed as an exact fraction from the stored double. The two differ for three reasons:

- At `p = 0.8` and `p = 0.9` the lower edge is often one above the exact edge. The stored 0.8 is above 4/5, so `b*(1-p)` falls just under a whole number, but `r` rounds to exactly `-p` and `p > |r|` fails. For `b = 10^8`, `p = 0.8`: 20000000 is refused, 20000001 is admitted.
- For `b` above 2^53 the doubles lose bits, so edges move by up to hundreds of units.
- For `b = 10^18` and `p >= 0.95` the band passes `u64::MAX`, so the last row is capped there and its difference is negative.

### The other classes

The spot gate first bounds the token index with `+0x180` (panic Location record `0x56f1fd8`), reads the key at `+0x178`, row stride 0x20, and calls the classifier with `(+0x10, key)`:

- 0: the band above.
- 1: tag 0x17f `Invalid spot`.
- Any other byte: no band. It calls the helper, and the gate admits only when the helper returns `v`, `v >= 1000` and `a <= v - 1000`. Otherwise tag 0xee `Price too large`. `b` and `p` play no part.

The helper `0x372b4b0` takes token id from the same rows, looks it up in a hash table at `+0x80` (16-byte entries, the value is a link), then looks the link up in a second table at `+0xe0` (0x90-byte records). A record holds two (word, token) pairs: word `+0x20` with token `+0x28`, word `+0x48` with token `+0x50`. It returns the word beside the matching token. Errors: 3 for first table miss or empty, 4 for second table miss or empty, 2 for neither token. The gate treats all of them as tag 0xee.

The perp gate calls its test `0x37e4fb0` on `rcx` first. Any nonzero low byte admits at once.

The wrapper `0x372efe0` is 37 bytes: bound, read key, tail jump to the classifier. `outcomes.tsv` lists the named cases.

## Implementation and comparison

not yet implemented

Reference check: `l1/action/vote_global.rs:524` tests only the asset index for `MaxOrderDistanceFromAnchor`. The 0.2 to 0.99 guard and tag 0x41 have no rule there. `l1/clearinghouse/oracle/oracle.rs:458` `price_limit_check` is a different shape: it takes a side, uses `anchor * (1 +- dist)`, has a default 0.20 and fixed hip3 ratios, and both edges are inclusive. Its error is `PriceTooFarFromOracle`, and the tag 0x5f text is not in the reference tree. These gates may be a separate check, so this packet does not claim that function is wrong. `OUTCOME_THRESHOLD_BIAS` of 1000 in `l1/exchange/impl_outcome.rs:25` is applied to an expiry there, while the bytes here compare it with `a`.

## Results and limitations

- Real runs: 52 named, 22984 grid, 92 cap and 3000 random cases, plus 700 edge runs, all equal to the specification. Outcomes are in `evidence.json` (6600 ok, 19450 tag 0x5f, 75 tag 0xee, 1 tag 0x17f, 2 panics).
- Mutation controls: each condition, immediate and field displacement in reached rows of the three functions is flipped once, 98 in all. 96 are killed. The 2 survivors are the `pshufd` immediates at `0x372b51a` and `0x372b5e3`, where the changed selector picks an equal dword.
- Rodata constants are not in the mutation sweep. The tests corrupt each of them and the walker refuses.
- The symbolic walk starts at the divide. The conversion before it is pinned by instruction sequence and constants, and the register mapping of `a` and `b` is shown by runs, not by the walk.
- Inputs: that `a` is the order price and `b` the reference price comes from the message text and a reading of one call site, not from generated evidence. `b` was not traced to a single source.
- The classifier values are stubbed. That class 0 means an ordinary token and other values mean an outcome token is inference from the reference names.
- The word `v` has no binary name yet.
- The test `0x37e4fb0` is stubbed, so which inputs skip the perp band is not covered.
- Whether a vote names an asset or dex, and how the state holding `+0x3980` or `+0x4400` is chosen, was not traced. Other stores of the field (`0x37526eb`, `0x4d7ae55`, `0x4d7c78a`) and the default value are unresolved. The serde key was tied to one reader only.
- Stubs show the calls made, not what a stubbed callee computes.
