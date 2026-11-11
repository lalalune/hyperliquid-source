# vaults: reconstruct the node #115 vault withdraw admission gate 0x44ab4a0 and prove it against the bytes

This packet makes the vault withdraw / transfer admission gate at `0x44ab4a0` (the 2,831-byte body in `l1/src/vault/mod.rs` that decides
whether a requested amount may leave a vault) reconstructible as a short executable rule list: how the fee base is summed over the
leader and an address set (saturating), how the requested address is found in the per-vault map (a VecDeque or a B-tree), how the unlock
date is checked, how the available amount becomes a ratio of the fee base, and in which order the nine error tags
`0xa 0xb 0xc 0xd 0xe 0xf 0x10 0x2a 0x11f` and the success record (tag `0x1a2`) are produced. The rule list in `tools/vault_withdraw_gate_115.py`
(`spec_gate`) was written from the control flow and is checked against the real bytes of the gate and of the deque binary search it calls,
run in a small x86-64 evaluator, over 12,064 generated cases with 0 mismatches in the result, the result record and the ordered list of
helper calls; 296 negative controls (30 named wrong readings, 18 structural controls, 248 byte edits of reached instructions) are all detected.

- Component ID: vaults (`l1/vault`; no TASKS row exists for vaults, the nearest dependency is RE-007 margin / risk)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: base `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was copied (labels from
  references/can1357-hl were not needed; every name below is an inference from the bytes)
- Claim status: observation for addresses, offsets, constants, branch order, error tags and call order; inference for the role names
  (fee base, available amount, fraction, lock duration); unresolved for the bodies of the helpers that are stubs here (listed below)
- Scope included and excluded: included - the gate body `0x44ab4a0..0x44abfaf` (622 decoded instructions) and the deque search `0x45578e0`
  (136 instructions) run as real code. Excluded - the per-address fee helper `0x44a9430`, the chrono and duration helpers, the available
  and locked amount hooks, memcmp, the panic and logging hooks (recording stubs with written contracts); every caller of the gate;
  the vault state's writers; no component gate is requested.

## Reproduce

Working directory: repository root, platform Linux x86-64, Python 3 standard library plus the shared `tools/fde_extents.py` and
`tools/elf_index.py`. The tool never runs the binary and never calls objdump or readelf.

```
python3 tools/artifacts.py verify
python3 tools/vault_withdraw_gate_115.py --out research/work-items/vaults-withdraw-gate-115
(cd research/work-items/vaults-withdraw-gate-115 && sha256sum -c MANIFEST.sha256)
python3 -m unittest tests.test_vault_withdraw_gate_115
```

The regeneration takes about 100 s and 310 MB; the output is byte identical under different hash seeds and time zones (two runs with
`PYTHONHASHSEED=1 TZ=Asia/Seoul` and `PYTHONHASHSEED=777 TZ=America/Los_Angeles` were compared with `diff -r`). The 26 tests take about 105 s.
The input digest is checked first and the tool stops on a mismatch.

## Evidence

Coordinates are ELF virtual addresses. All numbers come from the ELF bytes through the shared parsers; `call-sites.tsv` and
`function-rows.tsv` come from the tool's own decoder, not from binutils.

- Gate: FDE `0x44ab4a0..0x44abfaf`. Arguments (System V): `rdi` result record (0x28 bytes, written only through `[rdi]` as a u16 tag on error), `rsi` the vault state,
  `rdx` the 20-byte requested address, `rcx` a mode word (only the value 1 is special), `r8` an amount used in mode 1, `r9` a pointer
  to the 12-byte request date-time (day, seconds, fraction); stack: a second mode word (1 enables the remaining check), a signed minimum
  remaining amount, and a context record whose first word is handed to the locked-amount hook.
- Vault state fields read (`state-fields.tsv`, `layout` in the tool): tag word at `+0x00` (0, 1 or 2); an address-set B-tree at `+0x08` (root),
  `+0x10` (height), `+0x18` (length) used only when the tag is 2; the per-vault map at `+0x50` (word 0 is the VecDeque capacity, or `1<<63`
  for the B-tree variant; root `+0x58`, height `+0x60`; VecDeque pointer `+0x58`, head `+0x60`, length `+0x68`); lock duration f64 at `+0x78`;
  leader address `+0x8c`; self address `+0xa0`; a flag byte `+0xb6`. Map entries are 72 bytes in the deque (20-byte key, record at `+0x18`)
  and 48-byte records plus 20-byte keys (`+0x218`) in the B-tree node (length `u16` at `+0x2f6`, edges at `+0x2f8`). The record holds the
  allowed fraction (f64 at `+0`) and a 12-byte date-time at `+0x24`. The address-set node has keys at `+8`, parent index `+0xe4`, length `+0xe6`, edges `+0xe8`.
- Order of decisions (observation, each confirmed by the evaluator on all cases):
  1. fee base = fee(leader) plus fee(member) for the first `length` members of the set in tree order when the tag is 2, the root is non-null and
     the length is non-zero; each addition saturates at the i64 bounds and calls the overflow-log hook first; asking for more members than
     the tree holds reaches an `ud2`-style panic (`set-exhausted`). A base that is not positive gives error `0xa`.
  2. the requested address must be in the map (deque binary search `0x45578e0` with a 20-byte memcmp, or the B-tree descent with the memcmp
     hook, 20 bytes compared); absent, null root or empty gives `0xb`.
  3. unless the tag is 1: the lock duration (f64 seconds, converted by the duration hook, saturated to i64 nanoseconds, split by `/1e9`)
     is added to the record's time of day; carried whole days go to the date hook; a date hook result of 0 or an out-of-range carry selects the
     latest date constant `(2147473118, 86399, 999999999)`; the request date-time must be at or after the result, compared as (signed day,
     seconds, fraction), otherwise `0xc`. A negative, NaN or too large duration panics inside the duration hook.
  4. the amount is the mode-1 argument `r8`, or the available amount from the hook for every other mode value; the ratio is
     `(amount / 1e6) / (base / 1e6)` in binary64 (the u64 conversions use the 2^52 / 2^84 magic pair and are exactly rounded).
  5. ratio above the record fraction, or below `1e-8`, gives `0xe` (with a once-log hook call first when the flag word `0x64f01d8` is non-zero).
  6. limit = saturating truncation of `fraction * base`, floored at 0; if the limit is above the amount and the difference is below 5,000,000
     the result is `0x2a`. In mode 1 an amount above the available amount gives `0xd`.
  7. when the requested address equals the self address: `slack = (1 - ratio) * 0.05` must not exceed `1e-8 + (fraction - ratio)`
     (else the late-log hook and `0xf`), and `(fraction - ratio) * base` truncated must be at least 100,000,000 (else `0x10`).
  8. `taken` = saturating truncation of `base * ratio`; with the second mode word equal to 1, `base - taken` below the signed minimum gives `0x11f`.
  9. success: tag 1 writes kind 0 with the product as an f64, `taken`, the ratio; any other tag asks the locked-amount hook for the leader and writes
     either (when `taken <= locked`) kind 1 with f64 = ratio if the flag byte `+0xb6` is non-zero, else kind 0 (the f64 slot is then a clobbered
     register and is not claimed), or (when `taken > locked`) kind 1 with f64 = `max(ratio, 0.2)`.
- Constants read from rodata (`constants.tsv`): `1e6`, `1e-15` (minimum base), `1e-8`, `0.05`, `1.0`, `0.2`, the clamp pair `+-2^63`, the
  saturation threshold `9223372036854774784`, the infinity pair, and the latest date-time triple.
- Call sites (`call-sites.tsv`): 18 call sites - 2 direct calls of `0x44a9430`, 1 real call of `0x45578e0`, 14 indirect calls through
  slots `0x64e4ea8 0x64e0f70 0x64e0f78 0x64e0aa0 0x64eaae0 0x64df830 0x64e0b20 0x64e5078 0x64df9f0` and one `call *r13` that holds the memcmp slot `0x64dfb50`.
- Not reached by any case (`unreached.tsv`, 34 rows of the gate and one of the deque search): 5 padding nops, 2 jumps made dead by earlier
  tests, the `ratio-invalid` and `base-invalid` panic arms (they need an infinite or NaN ratio, impossible for a positive finite base and a
  u64 amount), the loop-entry panic, the remaining-amount overflow arm (needs `base > 0` minus a negative taken amount) and one deque jump.

## Implementation and comparison

Not a Rust implementation: the rule list is Python (`spec_gate` and the models in `tools/vault_withdraw_gate_115.py`), written separately from
the evaluator and compared with it case by case.

- Evaluator: the x86-64 subset already used by the other node #115 reconstruction tools, extended here by the one-operand signed multiply and
  the equal, unordered and not-less-than packed compare predicates. Real code: the gate and `0x45578e0`. Stubs: `0x44a9430` (fee by 20-byte key,
  default for unknown keys), duration, time-add and date-add hooks (contracts `model_duration`, `model_time_add`, `model_date_add`; they stand
  for chrono calls whose bodies are not reconstructed here), available and locked amount hooks, memcmp (byte difference), panic, logging hooks.
  Each stub checks its own arguments (context pointer, vault state pointer, key bytes, length 20) and records the call; the recorded list is
  part of the comparison.
- Cases: 12,064 = 64 named cases (one per terminal outcome, boundary and structure: unlock-date equality and one second short, day carry, the
  latest-date fallback, saturated duration, deque wrap positions, B-trees of height 0..2, 140-entry maps, address sets of 1..150 members and of
  511 and 1,023 members that reach the unrolled descent loops at heights 8 and 9, set length larger than the tree, null root, saturation up and
  down, a 16-byte-prefix key collision, the float edge `0.3 - 0.2` of the self bound) plus 12,000 pseudo-random cases from a fixed seed.
  Each case builds the heap image (B-tree nodes with parent links, deque rings with a head offset), runs the gate, and compares result, record bytes,
  heap (nothing outside the record may change) and ordered stub calls with the rule list. `outcomes.tsv` lists the outcome counts per store and tag.
- Negative controls (`measure.json`: 296 made, 296 detected, 0 equivalent): 30 named wrong readings in `variants.tsv` (for example comparing the
  date strictly, skipping the lock, wrapping the fee sum, a 16-byte key compare, a 1,000,000 excess threshold, an inverted kind flag, an unsigned
  minimum-remaining compare), each refused by at least one case; 18 structural controls in `structural-controls.tsv` (wrong digest, mid-function
  address, NOBITS address, truncated ELF, window ending inside the body, missing fee model, deque search not run as real code, int3 at the entry byte,
  removed hooks, tampered constants, flipped record and key bytes); 248 byte edits in `mutants.tsv` (86 condition codes, 92 field displacements,
  70 immediates of reached instructions, scored on 464 cases - the 64 named ones and every 30th random one - all killed).
- Memory: the harness allocates a 640 KB heap image so that the 511- and 1,023-member sets and a 140-entry tree fit; the tool stays under 310 MB.

## Results and limitations

- `measure.json`: cases 12,064, mismatches 0, negative controls 296, detected 296, equivalent 0; instructions reached 724 of the 758 decoded in the two bodies.
- The rule list reproduces the gate for every input that reaches it through the stubs; the stubs' own bodies (the per-address fee helper `0x44a9430`,
  the time-of-day and date additions, the duration conversion, the available and locked amount lookups behind slots `0x64eaae0` and `0x64e5078`) are
  not reconstructed, and the slot targets are not resolved here. The models of the chrono hooks are contracts chosen so that every branch of the
  gate is exercised; the gate's decisions are what is proven, not chrono behaviour.
- Role names (fee base, available amount, lock) are inferences; no reference source text was used. The leader and self address roles are inferred from
  which state fields are compared.
- Not a gate request: this is one function family of the vaults component, not a full-scope component gate; `research/progress.json` is untouched.
- Known source overlap: `RE-001-node115-vault-entry-guards` records a call site of `0x44a9430` inside `0x44ae810`, and
  `RE-001-node115-loc-edge-44abfa0` records one panic location edge inside this gate's frame; neither reconstructs this function.

Next question: reconstruct the per-address fee helper `0x44a9430` (two keyed lookups, a divide by 100 and a checked add) and the callers of
`0x44ab4a0` listed in `direct-callers.tsv` so the stub contracts can be replaced by real code.
