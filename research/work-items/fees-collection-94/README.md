# fees: node #94 fee collection path: dex credit and spot fee sweep

This packet shows where a fee goes after a fill: every call of `0x37067b0` pays a first amount to the dex deployer row and a second amount to `0xfe..fe`, or in mode 3 splits all of it by `extra_destination_fractions` and pays the rest to `destination`, so a reconstruction can now write the fee credit and the per-step spot fee sweep as exact integer rules.

- Component ID: fees
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c` (repository), references/can1357-hl at the submodule commit of that tree
- Claim status: observation for instruction behaviour, offsets, constants and call sites; inference for the meaning of mode 3 and of the 0xfe address; unresolved for the name of the dex mode byte
- Scope included: `0x37067b0` (whole function), `0x26fe810`, `0x4ce76a0`, `0x4ce7b90` (whole functions), keys of 4 fields, a byte census of 12 credit call sites and 13 fee tree sites
- Scope excluded: the bodies of callers, `0x3596940`, `0x339b590`, `0x33acfe0`, `0x3bac6e0`, `0x3379490`, `0x32814c0`, `0x375fb50`, `0x371d120` (stubs that check their arguments), and the writers of the tree at state `+0x420` (listed, not evaluated)

## Reproduce

From the repository root:

```sh
python3 tools/artifacts.py verify
python3 tools/fees_collection.py --out research/work-items/fees-collection-94
python3 -m unittest tests.test_fees_collection
(cd research/work-items/fees-collection-94 && sha256sum -c MANIFEST.sha256)
```

The tool checks the input SHA-256 first, reads ELF bytes in Python, uses only the standard library plus `tools/elf_index.py` and `tools/fde_extents.py`, starts no external program and does not run the node. It takes about 6 minutes on 3 workers. Output is byte identical across runs, hash seeds and time zones.

## Evidence

Coordinates are ELF virtual addresses. Ranges come from `.eh_frame`, and the table decoder must land on each FDE end. All numbers are in `evidence.json`.

| function | end | FDE | instructions | executed |
|---|---|---|---:|---:|
| `0x37067b0` | `0x3707000` | `0x11a4ff8` | 469 | 459 |
| `0x26fe810` | `0x26fecfe` | `0x10ed53c` | 268 | 246 |
| `0x4ce76a0` | `0x4ce7b8e` | `0x12df958` | 268 | 246 |
| `0x4ce7b90` | `0x4ce807e` | `0x12df9ac` | 268 | 246 |

### Dex credit `0x37067b0`

Reached only through slot `0x5774918`. Arguments: `rdi` dex row, `rsi` first amount `a`, `rdx` second amount `b`, `rcx` fee tracker. `credit-sites.tsv` lists the 12 `call [rip+d]` sites.

```text
total = sat_add(a, b)                               recorder at l1/src/qtys/impl_ntl.rs:62
if dex[+0x230] != 3 and a >= 0 and b >= 0:
    pay(row_address(), a)
    rest = b
else:
    rest = total
if dex[+0x230] == 3:
    if tree != null and tree_count != 0:
        base = rest as f64                          fixed before the loop
        for (who, share) in tracker[+0x78], key order, tree_count steps:
            part = to_i64(share * base)
            rest = sat_sub(rest, part)              recorder at impl_ntl.rs:62
            pay(who, part)
    pay(tracker[+0xa8], rest)
else:
    pay(0xfe x 20, rest)
usd = to_i64(total as f64 * dex[+0x2a0])
usd == i64::MIN panics at library/core/src/num/mod.rs:320:5
usd clamped to [-0x147ae147ae147ae, 0x147ae147ae147ae]
tracker[+0x140] = sat_add(tracker[+0x140], usd)     recorder at l1/src/qtys/mod.rs:830
```

- `row_address()`: `dex[+0x208]` points to a row. Bit 0 of row `+0x9d` set picks the address at row `+0x9e`, else the address at row `+0x74`.
- `pay(who, x)`: `0x3596940(dex + 0xf8, who)` gives a row, `0x339b590(dex + 0x188, who)` marks it, row `+0` gets `sat_add(row, x)`. Then row `+0x20` is read again: non-zero to zero calls `0x33acfe0(dex + 0x158, who)`, zero to non-zero calls `0x339b590(dex + 0x158, who)`. No instruction of this function writes row `+0x20`.
- `to_i64`: NaN and both infinities give 0, other values clamp to the range of 2^63 and truncate, and a value above 2^63 - 1024 gives `i64::MAX`.
- In mode 3 the deployer row is not paid. With a negative `a` or `b` outside mode 3, all of `total` goes to `0xfe..fe`.
- The total word adds `total`, not the protocol part. Fractions are not normalised: the sum may pass 1 and `rest` goes negative.
- A tree shorter than the count word panics at `library/alloc/src/collections/btree/navigate.rs:534:47`.

Keys, from the serializers: `+0xa8` is `destination` and `+0x78` is `extra_destination_fractions` (`0x1e87500`, `0x1ebd6d0`), `+0x140` is `total_fees_collected` and `+0x148` is `total_spot_fees_collected` (`0x23382e0`).

### Spot fee sweep `0x26fe810`, `0x4ce76a0`, `0x4ce7b90`

One direct call each: `0x222a0e9` in `0x22297c0`, `0x4716cb2` in `0x47162d0`, `0x470f27d` in `0x470e9a0`. The copies differ in state offsets and rel32 words only (`evidence.json` `layout`).

| field | `0x26fe810`, `0x4ce7b90` | `0x4ce76a0` |
|---|---:|---:|
| gate byte | `+0x3ac8` | `+0x4548` |
| dex array | `+0x5c0`, count `+0x5c8` | `+0x1040`, count `+0x1048` |
| tracker | `+0x5d0` | `+0x1050` |

```text
if state[gate] != 0: return
for token in keys of the map at state +0x2e0 (0x3bac6e0):
    v = tree[state +0x420][token]; a missing token is skipped
    if token == 0:
        if v < 100: continue
        q = v / 100
        tree[0] = v - 100 * q
        dex = first row of the dex array; an empty array panics with Result::unwrap, tag 0x141
        tracker[+0x148] = sat_add(tracker[+0x148], q)       unsigned
        dex[+0x238] = sat_add(dex[+0x238], q)               signed
        credit(dex, 0, q, tracker)
    else:
        tree[token] = 0
        px = tree[state +0x250][token], or 0x375fb50(state + 0x90, token)
        (flag, value) = 0x32814c0(v, token, px, state + 0x90)
        amount = value if flag bit 0 is set and value < 0x28f5c28f5c28f5c else v
        u = amount / 100
        tracker[+0x140] = sat_add(tracker[+0x140], u)       signed
        tracker[+0x148] = sat_add(tracker[+0x148], u)       unsigned
        0x371d120(state + 0x80, 0xfe x 20, token, 0, v, 0)
```

`b` is the only amount a token 0 sweep passes, so `a = 0` and the deployer row is paid 0. All 4 recorder Locations are in `l1/src/qtys/mod.rs`, lines 829 and 830. `q` and `u` floor, and the token 0 remainder stays in the tree for the next step.

### Census

- `credit-sites.tsv`: slot `0x5774918` is the only slot holding `0x37067b0`. Three sweep sites, `0x37113f1` in `0x3710a70` (the fill host of `fees-trade-fee-94`), and 8 more.
- `tree-sites.tsv`: 13 `lea r64, [r64 + 0x420]` sites in functions that also call `0x371d120` directly, 7 of them right after that call. The `0x26c7a92` caller passes `rcx = 1` where the sweep passes 0.

Fields seen, with names where the binary gives one, are in `evidence.json` `fields`. `reference-diff.tsv` has 4 rows.

## Inferences

Kept apart from the observations above.

- `a` and `b` are the deployer and protocol parts of `fees-trade-fee-94`, side `+0xc0` and `+0xc8`. The fill site `0x37113f1` passes `r13` and `r12`, signed saturating sums built at `0x37110fd` and `0x371110c` over the two passes of the side loop in `0x3710a70`. The host loads output `+0x68` and `+0x70` near the same place, which is the deployer and protocol pair of that packet, so one credit would cover both sides of a fill. This was read by hand and the host body is not evaluated here.
- Mode 3 is a dex with no deployer, likely the core dex. Nothing here names the byte.
- The `0xfe..fe` address is a system sink for protocol fees of a deployed dex and for spot fees in other tokens. Whether its balance is used later is not traced.
- The tree at state `+0x420` is fees collected per spot token: the sites after `0x371d120` take an amount from a user with `rcx = 1`, then look up the same token here.
- `v / 100` moves a 1e-8 amount to 1e-6 USD units. The binary shows the division only.

## Implementation and comparison

Rust: not yet implemented. Comparison is between the decoded instructions, interpreted in Python, and a separate closed-form model in the tool.

- 1046 vectors, 0 mismatches. 96 groups. Input records fault on unset bytes; `pay` rows, tree nodes and the whole state, dex and tracker are compared after each run, so a stray write fails. The call log compares every stub call in order with its arguments.
- B-trees use real node layouts, with parent links for the fraction tree, up to height 17 so the unrolled descents run. The real `0x37067b0` runs nested in the sweep in all 3 copies.
- Stubs flip row `+0x20` and clear the tree root to reach branches that nothing in these functions can reach alone. Those vectors show the branch, not a reachable state.
- 636 byte mutants over all 4 functions: 622 killed, 14 equivalent with reasons in `mutations.tsv` and `evidence.json`, 0 unclassified.
- 49 unit tests pass, with negative controls for the digest, FDE start, out-of-range address, `.bss` read, pins, f64 constants, key text, changed instruction bytes and a wrong model.

## Results and limitations

- Instructions executed: 1197 of 1273. The rest: 24 padding plus the ranges in `evidence.json` `unexecuted`: 2 jumps proved dead, the `ud2` after no-return calls, and unwind clean-up.
- Bytes alone: no state was read, so no real mode, fraction or balance is claimed. Amount units and the `+0x420` writers are not evaluated, and the dex mode byte stays unnamed.
- `0x32814c0` and `0x371d120` are stubs, so the price result and the spot balance change are arguments checked, not computed.
- #115 is not checked. No gate is requested.

Next question: what writes dex `+0x230` and the fraction tree at tracker `+0x78`, and does a real dex row hold mode 3 for the core dex?
