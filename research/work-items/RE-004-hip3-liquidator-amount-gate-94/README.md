# RE-004: what does node #94 accept as the amount of a hip3LiquidatorTransfer action?

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the check order, the constants and the amount classes; inference for "quote tokens", the 1e-6 unit and the meaning of dex id 0; unresolved items are listed under limits
- Scope included and excluded: included are the three gate copies `0x27551e0`, `0x4d77dc0`, `0x4d77fe0` and their one-call wrappers `0x1e641e0`, `0x46bd030`, `0x46bcf30`. Excluded are the runners `0x2731870`, `0x4d3d0f0`, `0x4d401d0` and everything they call, which is where the ledger moves. The runners and the registry lookup are stubbed as edges.

## Reproduce

Working directory is the repository root. Platform Linux x86-64, Python 3.12.3, standard library only. The binary is read as bytes and never run. No external program is called, so the binutils version cannot change a result.

```
python3 tools/artifacts.py verify
python3 tools/hip3_liquidator_gate.py --out research/work-items/RE-004-hip3-liquidator-amount-gate-94
python3 -m unittest tests.test_hip3_liquidator_gate
```

The tool refuses any input whose SHA-256 differs. It uses `tools/elf_index.py` for sections and `tools/fde_extents.py` for FDE records. Output is byte-identical between runs.

## Evidence

Addresses are virtual addresses. `.text` VA minus file offset is 0x1000; `.rodata` VA equals file offset.

### Which action this is

- `.rodata` holds `struct Hip3LiquidatorTransferAction with 3 elements` and `hip3LiquidatorTransfer`, addresses in `evidence.json`.
- `.rela.dyn` holds 3 serde field lists whose names are `dex`, `ntl`, `isDeposit` (`field_lists`).
- The tag 0x185 Display arm gives `Must deposit or withdraw multiple of 1000 quote tokens`. A byte scan of `.text` finds that tag written at 3 places, one in each gate (`tag_0x185_writes`).
- The wrappers read the same three fields from the action: name at `+8`, `+0x10`, ntl at `+0x18`, flag at `+0x20`.

### Boundaries

`gate-copies.tsv` has one row per copy: FDE, 538 bytes and 128 instructions each, one direct call site each, inside the wrapper named on the row. No `.rela.dyn` pointer to a gate has a `call [rip+x]` user.

`copy-differences.tsv` compares the copies row by row against `0x27551e0`. Only three rows differ beyond the code shift: the runner call in both copies and, in `0x4d77dc0`, the registry offset `0x1038` where the others have `0x5b8`. Branches agree relative to the function and slots agree as absolute addresses.

### Check order

Arguments: `rdi` result, `rsi` state, `rdx` user, `rcx` owned action copy. The first failure wins:

| Step | Test | Result |
| --- | --- | --- |
| 1 | name length >= 101 | tag 0x143 `Invalid input length` |
| 2 | ntl >= `0x0ccccccccccccccc` | tag 0x13f `Invalid input number`, with ntl at `+8` |
| 3 | ntl == 0 | tag 0x2f `Deposit amount cannot be zero.` if the flag is set, else tag 0x30 `Withdrawal amount cannot be zero.` |
| 4 | ntl not a multiple of 1e9 | tag 0x185 |
| 5 | lookup through slot `0x5774708` fails | its 0x60-byte error passes through unchanged |
| 6 | word at lookup record `+0x30` == 0 | tag 0x141 `Invalid perp DEX` |
| 7 | none | runner called; it takes the name |

Every error path frees the name once, at its capacity. The success path does not. Error results write only the tag, plus the ntl word on step 2.

The runner receives `rdi` result, `rsi` state, `rdx` a 20-byte copy of the user, `rcx` the dex word, `r8` a pointer to the word 4, and `r9` seven words: capacity, name pointer, name length, pointer to the dex word, user, pointer to ntl, pointer to the flag. The stub checks each one.

### The multiple test

```
imul  rax = ntl * 0x8e47ce423a2e9c6d
ror   rax, 9
cmp   rax, 0x44b82fa0a
jb    pass
```

`multiple_proof` checks from the constants that this is exact for all 2^64 inputs:

- 1e9 = 5^9 * 2^9, and the multiplier times 5^9 is 1 mod 2^64.
- The map `f(x) = ror(x * m, 9)` is a bijection of u64, being an odd multiply then a rotate. `preimage` inverts it, checked in both directions on 20000 values.
- For `x = 1e9 * q` with q below 2^55, `f(x) = q`.
- The bound 18446744074 is the number of multiples of 1e9 in u64.

So the multiples fill the values below the bound, and being a bijection no other input lands there. `FIRST_ESCAPE`, 290448384, is the input with `f(x)` equal to the bound. It is below 1e9 and is one of the named cases.

### Amount classes

`amount-classes.tsv` covers all 2^64 values:

| Class | Values | Result |
| --- | --- | --- |
| 0 | 1 | tag 0x2f or 0x30 |
| below the cap, not a multiple | 922337202763140376 | tag 0x185 |
| 1e9 * q, q in `1..=922337203` | 922337203 | lookup, then runner |
| cap and above | 17524406870024074036 | tag 0x13f with the value |

The largest admitted ntl is 922337203000000000. The cap is `i64::MAX / 10` rounded down.

`AMOUNT_READS` pins every instruction that names `rbp`, which holds ntl: load, compare with the cap, zero test, multiply, the store into the 0x13f result, the store for the runner, and the save and restore. So those three tests are the only decisions on ntl, and the classes are complete. `state_reads` finds no memory read based on the state pointer in any copy, so the gate has no token, decimals or chain input.

### Wrappers

Each wrapper clones the name, calls the gate, and returns first byte 0xd when the gate tag is 0x186, or first byte 0xe with the 0x60 gate bytes at `+8`. `wrappers.tsv` has 3 real-byte cases per copy, including an empty name, which uses the dangling pointer 1 and allocates nothing.

### Inferences

These are readings of the observations above, not observations.

- The flag is `isDeposit`, from the field list and the two zero texts.
- ntl is in units of 1e-6, so 1e9 is 1000 tokens as the error text says. The gate does not read a token, so this holds only if every quote token uses that unit on this path. Spot wei decimals are not in the gate.
- The word at record `+0x30` is a dex index, and 0 is the first perp dex, refused because HIP-3 names deployed dexes. Its only uses here are the zero test and the runner arguments.

The reference has no handler for this. `rg -i hip3Liquidator references/can1357-hl` finds one comment listing action names, and the Display text of tag 0x185 is absent.

## Implementation and comparison

Not yet implemented in Rust. The comparison is real bytes against a specification written from the claim (`spec`).

Real instructions run in a Python evaluator. Stubs: the free slot, the lookup slot and the runner in the gate; alloc, copy and the gate in the wrapper. Each stub checks its arguments, and the free slot checks pointer, capacity and that it runs once. Unwritten result bytes must keep their fill pattern.

| Check | Count | Result |
| --- | --- | --- |
| Named cases, each copy | 39 | 0 mismatches |
| Fixed-seed random cases, each copy | 4000 | 0 mismatches |
| Amount classes, ends and spread interior points, each copy | 331 real runs | closed form holds |
| Rotate map, inverse in both directions | 20000 values, 6 fixed points | holds |
| Wrapper cases, each copy | 3 | as above |
| Mutations of reached conditions and immediates, all copies | 72 | 72 killed |

Every conditional branch ran in both directions, except the one in the unwind landing pad at `+0x200`, which only a panic in the runner or lookup reaches. `evidence.json` lists those 6 directions, and a change to the list fails the tool.

## Results and limitations

- The runners are stubbed. Whether the amount later meets a balance or a depositor limit is out of scope here.
- The registry lookup is stubbed. Which names it accepts was not read.
- Why the name limit is 101 was not traced. Other actions may share it.
- Whether a wire value at or above the cap reaches this gate depends on the ntl deserializer, which was not read.
- The real dispatch to the wrappers was not traced in this packet.
- Requests no progress gate.

Next question: what do the runner closures do with the ntl word: which balances move, what the `max_n_depositors` limit behind tag 0x184 counts, and whether a withdrawal is limited by a recorded deposit?
