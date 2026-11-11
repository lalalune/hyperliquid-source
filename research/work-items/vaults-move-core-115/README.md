# vaults: reconstruct node #115 vault move core 0x44ae810, its leader-share check and the four helpers it runs

- Component ID: vaults
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`
- Claim status: observation (byte-level behaviour reproduced by an evaluator) plus inference (field and rule names)
- Scope included and excluded: the whole body `[0x44ae810, 0x44af2e1)` (2,769 bytes, 606 instructions) is evaluated on
  its real bytes; the four helpers it calls through relocations/direct calls - `0x421a3c0`, `0x421a520`, `0x14ca350`,
  `0x45578e0` - are evaluated on their real bytes too. Seven further callee bodies (plus two panic entry points and the imported `memcmp`) are
  recording contract stubs (listed below). The binary is never executed.

This packet makes the vault "move" core reproducible as ordinary code: from the bytes it now fixes the ordered gate
list (two reject codes for a non-leader caller), the vault-value sum over a parent vault's child set with
saturation, the leader-share rule (the leader's position times its stored weight, divided by the post-move vault
value, must reach 0.05 and the position itself 1e-7), the balance debit/credit with saturating overflow handling, and the
per-address record update (`u64 += amount`, `i64 += amount`, 12 bytes of auxiliary data overwritten) together with the
exact 0x30-byte result record - and it proves each of them with 10,400 whole-body cases and
8,000 direct helper cases that agree with the Python model byte for byte.

## Reproduce

```
python3 tools/artifacts.py verify
python3 tools/vault_move_115.py --out research/work-items/vaults-move-core-115
python3 -m unittest tests.test_vault_move_115
```

The tool checks the SHA-256 of the node #115 binary first and fails otherwise, uses only the standard library plus
`tools/fde_extents.py` and `tools/elf_index.py`, never starts a subprocess and never executes the binary. It writes
`bodies.tsv`, `instructions.tsv`, `callees.tsv`, `constants.tsv`, `cases-sample.tsv`, `helper-cases-sample.tsv`,
`controls.tsv`, `equivalent-mutants.tsv`, `unreached.tsv`, `summary.json` and `measure.json` deterministically
(two regenerations are byte-identical). `MANIFEST.sha256` covers every file in this folder. Coordinates are ELF virtual
addresses. Output of all runs: no files outside the chosen folder.

## Evidence

Calling convention observed at entry (all derived from register use in the 606 instructions):
`rdi` = 0x30-byte result record, `rsi` = vault object, `rdx` = pointer to the 20-byte source address, `rcx` = signed
amount, `r8` = pointer to 12 auxiliary bytes, `r9d` = flag (only `r9b` is tested), first stack argument = pointer to
three words (`[0]` = exchange context pointer whose `+0x4a8` is a signed balance, `[1]`, `[2]` passed through).

Vault object offsets used by the body: `+0x00` mode word (tested as the full qword against 1 at entry, and as the low
dword against 1 and 2 later), `+0x08/+0x10/+0x18` root, height and count of a B-tree **set** of 20-byte child addresses
(node: parent `+0x00`, keys `+0x08` stride 20, parent index `+0xe4`, length `+0xe6`, edges `+0xe8`), `+0x50..+0x68` a
two-variant record table (`+0x50 == 0x8000000000000000` selects a B-tree map whose nodes hold 11 values of 0x30 bytes
at `+0x00`, parent `+0x210`, keys `+0x218`, parent index `+0x2f4`, length `+0x2f6`, edges `+0x2f8`; any other value is the
capacity of a ring buffer with pointer `+0x58`, head `+0x60`, length `+0x68` and 0x48-byte elements: 20-byte key padded
to 0x18, then the 0x30-byte record), `+0x8c` the vault's own 20-byte address, `+0xa0` the 20-byte leader address and
`+0xb5` a policy byte. A map record is: `+0x00` f64 weight, `+0x08` u64 total, `+0x10` i64 net, `+0x24` 12 bytes.

Flow reconstructed in `model` (every numbered step is a branch or store of the bytes; `constants.tsv` and
`callees.tsv` hold the addresses and values read by the tool):

1. Gate 1: if the mode qword is exactly 1 and the source address differs from the leader address -> reject `0x16`.
   Gate 2: if the policy byte is 0 and the addresses differ -> reject `0x17` (gate 1 wins when both fail). Rejects write
   `0x8000000000000019` to result+0 and the code to the u16 at result+0x10.
2. `value(vault address)` (callee `0x44a9430`, stubbed) starts the vault value `v`. If the mode **low dword** is 2 and
   the set root and count are both non-zero, every child address is visited in key order and `value(child)` is added
   with signed saturation; each overflow calls the overflow reporter with one of six panic-location constants.
3. If `v < 0`, `0x421a3c0` (real bytes: equality with one of eight 20-byte constants) must accept the vault address,
   otherwise reject `0x09`.
4. Leader-share check, only when `r9b == 0` and the mode low dword is not 1 and the addresses differ and
   `0x421a520` (second set of eight constants) rejects the vault address: look the **leader** up in the record table
   (absent -> reject `0x02`); `q = saturating_i64(v * weight)` (NaN/inf give 0), `lead = q / 1e6`;
   `total = max(v, 0) + amount` as an unsigned 64-bit add (a carry reports an overflow and saturates to u64::MAX; this is
   reachable with a negative amount); reject `0x02` unless `lead >= 1e-7`; `0x14ca350` computes `lead / (total / 1e6)` as a
   checked division and the result must be a finite quotient that is `>= 0.05` (NaN would pass) else reject `0x02`.
5. `available(ctx, source)` (stub); a negative amount panics through the formatted-panic callee; if `available < amount`
   (unsigned) the 0x34-tagged diagnostic is dropped and the result is reject `0x2d`.
6. `debit(ctx, source, amount)`, balance `-= amount` (saturating, reporter on overflow), `credit(ctx, vault address,
   amount)`, balance `+= amount` (the add-overflow branch is provably dead: it undoes a subtraction), then the settle
   callee `0x44ad9e0` with the vault, source, amount, `v`, the aux pointer and the three context words.
7. Record update for the **source** address (absent -> unwrap panic): `u64 += amount` (carry -> report, saturate),
   `i64 += amount` (overflow -> report, saturate), the 12 aux bytes overwrite `+0x24..+0x30`.
8. Success result: head `0x8000000000000004`, f64 `amount / 1e6` at +8, the vault address at +0x10..+0x24.

Real-byte helpers (all four run in the evaluator, and 8,000 direct cases cover inputs the owner cannot produce):
`0x421a3c0` and `0x421a520` accept exactly eight 20-byte addresses each (16 + 4 byte `pcmpeqb` pairs; a pool entry whose
upper 12 bytes are not zero would never match - none of the 16 is like that); `0x14ca350` rejects NaN/inf, a negative
numerator below the tiny-negative constant, and a denominator below the minimum constant, clamps a tiny negative numerator
to zero, and rejects a non-finite quotient; `0x45578e0` is the two-slice binary search over the ring (`al` = 1 and
`rdx` = insertion index when absent).

Stubbed callees (recording contract stubs; arguments are compared, results come from the case): `0x44a9430` value of an
address, `0x44ad9e0` settle, `0x4472ea0` credit, `0x447db40` debit, `0x446bdd0` available amount, `0x44e0810` diagnostic
drop, overflow reporter `0x4524e40` (starts with `lock cmpxchg`, outside the supported subset), panics `0x1680c10` and
`0x1680c30`, and the imported `memcmp` (a real byte-wise compare).

## Implementation and comparison

`tools/vault_move_115.py` contains (a) the x86-64 subset evaluator of the repository's other 115 serializer tools,
extended here with `cdqe`, parity conditions and the scalar/packed double-precision forms the body uses (`cvtsi2sd`,
`cvttsd2si`, `mulsd/divsd/addsd/subsd`, `minsd/maxsd`, `ucomisd`, `subpd`, `punpckldq`, `unpckhpd`, `movq/movsd`); (b)
fixture builders that lay out real B-tree set/map nodes of height 0-2 with random shapes, ring buffers with random head
and spare capacity, the vault object, the exchange context and the stack argument; (c) `model`, the Python reconstruction
with mutation hooks; (d) the case generator (10,400 whole-body cases, deterministic SHA-512 streams;
outcomes: `ok` 3326, `panic:0x648c1a0` 537, `panic:0x7d3212:0x2b:0x648c598:0x648ba38` 1292, `reject-0x16` 1003, `reject-0x17` 1106, `reject-0x2` 1266, `reject-0x2d` 926, `reject-0x9` 944); (e) the control runner. Each case is executed on the real bytes and compared field by field with
the model: panic location or absent, the ordered stub-call list, the 0x30-byte result, every byte of every fixture region
(vault, set nodes, map nodes, ring, key, aux, closure, context) and the callee-saved registers, stack pointer and return
value. Shape independence is part of the proof: the model never sees node layout, only the abstract set/map.

Negative controls (304, all in `controls.tsv`): 33 model mutants (30 whole-body rules, two of them on the checked division, plus 3 helper-only rules),
13 corrupted-world runs where the machine runs a perturbed input against the unperturbed model, 3 binary-level
refusals (digest, read outside file-backed sections, unsupported opcode) and one byte flip per immediate, condition code
and constant-pool displacement of every executed instruction of the five bodies.

## Results and limitations

- Whole-body cases: 10,400, mismatches 0; helper cases 8,000; total
  `cases` = 18,400 (`measure.json`). Owner instructions executed: 554 of
  606; the rest are listed in `unreached.tsv` (unrolled tree-descent loops for heights >= 8,
  which no 64-bit key count can reach with 11-key nodes; the dead balance-add overflow; two unwrap panics inside the
  set iterator that valid trees cannot hit; padding; and in the ring search the single `jmp` for an empty
  second slice, which `head < capacity` rules out).
- Controls: 294 detected, 10 equivalent (`equivalent-mutants.tsv`), 304 total.
- Not claimed: the semantics behind the stubbed callees (value of an address, settle/share bookkeeping), the names of
  the fields, and that this is the vault deposit or withdraw action of the exchange - only the body's input/output
  behaviour is. No component gate is requested.
- Next question: `0x44ad9e0` (2,367 bytes, calls `0x44a9430` twice, rewrites the per-address weights after a move) is
  the largest remaining callee; `0x44a9430` (895 bytes) and the debit/credit pair `0x447db40`/`0x4472ea0` follow.
