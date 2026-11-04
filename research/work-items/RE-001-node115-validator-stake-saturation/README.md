# RE-001: validator-stakes saturating reductions in node #115

- Component: `consensus`, preparatory static mapping for RE-008.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: how does the `validator_stakes.rs` predicate accumulate selected
  and full-stream weights, handle lookup misses and arithmetic overflow, and
  compare its two returned sums?
- Result: the selected functions use **saturating u64 accumulation**, skip
  missing selected keys, and compare `2*S < 3*B` using wide products. They keep
  iterating after saturation. This is a different path from the checked-sum
  quorum-policy routine mapped in #987; its failure behavior cannot be reused.
- No Rust implementation, captured execution, emulation, complete consensus
  policy, accepted gate or whole-component denominator is claimed.

## Scope and evidence

All addresses are original ELF virtual addresses, with half-open ranges.
`records.json` also retains file offsets and actual FDE/CIE identities. GNU
objdump and LLVM independently cover every byte and agree on instruction starts;
GNU readelf independently checks the three FDE records.

| Role | FDE range | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Source-associated predicate | `0x4d3e1a0..0x4d3e30d` | 365 | 99 |
| Selected-key fold | `0x4e44c00..0x4e44e03` | 515 | 126 |
| All-weight fold | `0x4e406f0..0x4e4098d` | 669 | 155 |

The export denominator is **3 complete FDE bodies / 1,549 bytes / 380
instructions**, with 9 call instructions. These are static exports, not
source-built matching windows or a complete semantic proof of every body.
`obligations.json` binds 25 instruction spans to the facts below. No operand
normalization is used.

The predicate passes Location `0x649cd70` to the first fold and `0x649cd58` to
the second. Their `R_X86_64_RELATIVE` entries point to `0x44ae86`, the 38-byte
`node/src/consensus/validator_stakes.rs` string; metadata gives line 30 column 15
and line 26 column 15 respectively. This establishes source association, not
original Rust names. The first fold does not use its incoming RSI Location in
its body. The second overwrites RSI on the fast path; neither is described as
panicking on overflow because of a supplied Location.

### Inputs and selected-key reduction

At predicate entry, RDI is a map-shaped object `M`, and RSI is a key-iterator
source `K`. The predicate constructs an 88-byte stack descriptor containing
`K`'s words, `M`, and a pointer to a saved `K` pointer, then calls `0x4e44c00`.
The exact source types and complete iterator invariants remain unknown.
The helper copies the descriptor locally and obtains a key pointer from
`0x5138730`; a null return ends iteration. It reads `M` from copied descriptor
`+0x48`. That iterator is a helper boundary, not implemented here.

`NEG` followed by `JNO` distinguishes the map's first qword from the sentinel
`0x8000000000000000`; only that exact word takes the tree-shaped branch.

| Selected-key route | Observed behavior |
| --- | --- |
| Sentinel/tree-shaped map | A null root at `M+8` skips the key. Each node compares 20-byte keys at node `+0x60`, using count u16 `+0x13e`. The import at slot `0x64dfb50` is symbol 12, `memcmp`. Equality selects weight node `+8+8*i`. A non-equal leaf search skips the key; deeper search follows child pointers at `+0x140+8*i` while decrementing the saved depth. |
| Other/flat map | Calls `0x57f54e0(M,key)`. If AL bit 0 is set, or returned RDX index is at least `M+0x18`, it skips the key. Otherwise it adds `M+0x10` to the index, subtracts capacity `M+0` once if needed, and addresses the qword at `M+8 + 32*slot + 24`. |
| Found weight | Adds the weight to the accumulated sum at `0x4e44c65`, clamps to `u64::MAX` on unsigned carry through the two CMOVB instructions, and asks for the next key. |
| No keys / all misses | Returns zero / preserves the previous accumulated sum. A miss is not an error return from this fold. |

The flat address formula assumes a canonical head `0 <= head < capacity`,
`length <= capacity`, and valid nonwrapping readable storage. The total-span
builder below tolerates a larger head domain; those premises are deliberately
not conflated. Status interpretation is only the low-bit and bounds checks
observed **after** the lookup returns. No search-algorithm equivalence is claimed.

No local deduplication or early return at `u64::MAX` exists in this fold. If the
upstream iterator produces a repeated key, that occurrence can add its weight
again. This conditional statement does **not** establish that a valid key-set
iterator admits duplicates, nor that its map remains unchanged during callbacks.

### All-weight reduction and the final predicate

After retaining the first fold's raw RAX in RBX (`B`), the predicate creates a
second iterator descriptor from `M` and calls `0x4e406f0`. Its returned RAX is
`S`. These are two sequential observations, not an atomic snapshot guarantee.

The non-sentinel map is converted to two contiguous spans with 32-byte rows.
For capacity `0 < c < 2^63`, `0 <= head < 2*c`, `0 <= length <= c` and nonwrapping
storage, it normalizes the head with at most one subtraction, then splits at
capacity. A zero length creates two empty spans. The `tag == 2` fold reads each
row's qword `+24`, saturates at every addition, and swaps to the second span.
The code also returns if the first active cursor is null; valid nonempty spans
are assumed to be nonnull. This malformed-input exit is not modeled as a row.

For other tags, the fold has a tree-shaped traversal. Its accumulation step at
`0x4e4078a` reads node `+8+8*i` and uses the same saturating addition. An initially zero
remaining count returns zero; exhaustion after progress returns the accumulated
sum. A clear low tag bit on the nonempty non-flat route and exhausted parent
routes call the failure helper via slot `0x64df830`. Full parent/child traversal,
validity, unwinding and panic behavior are not proved. The exported instructions
and their data/call bindings are retained so a later reconstruction can close
those questions.

On normal completion of both folds, the predicate returns AL = 1 exactly when

```
2 * S < 3 * B
```

using unsigned products wider than 64 bits: `SHR 63` supplies the high limb of
`2*S`, `MUL 3` supplies both limbs of `3*B`, and `CMP; SBB; SETB` implements strict
comparison. Zero/zero and exact ties return false. The source-associated labels
“selected” and “all” describe this dataflow; they are not proof of the full
protocol's stake population, quorum eligibility, uniqueness or membership rules.
See [PROOF.md](PROOF.md) for the saturation argument and comparison limits.

### Call boundaries and existing work

The census finds four direct calls to the two folds: two in the predicate and
two in `0x2e112f0..0x2e11afb`. The predicate has one RELATIVE slot, `0x64e6a98`,
used by two instruction-aligned RIP-relative calls at `0x28aa141` and
`0x595bc5d`. Every candidate's enclosing FDE was fully decoded with Capstone
before accepting its instruction boundary. These six sites are **context**;
their bodies and higher-level semantics are not new claims. Only E8 and
RIP-relative FF15/FF25 forms in `.text` were searched, so arbitrary vtable and
register calls remain unmeasured.

- #987 and #1928 cover a separate **checked** fold and quorum-policy path at
  `0x3bcad50`, `0x422e280` and `0x43516d0`. Their wide-product argument is
  acknowledged prior work; the new result is this distinct saturating path and
  its miss/representation behavior.
- #2033 already lists the shared lookup `0x57f54e0` while studying proposer
  selection. #2308 already records calls to shared key iterator `0x5138730` in
  heartbeat classification. Those helpers are boundaries here and earn no new
  measured-body credit.
- #879 studies node #94 forceIncreaseEpoch, with a checked total and a
  saturating selected sum. Here both folds saturate. This packet does not claim to discover saturating stake arithmetic in
  general or remap that action. It establishes the previously unrecorded #115
  consensus helper cluster above, its representations, source bindings, and
  precise binary evidence.
- The all-state PR audit and base-history scan found only path-inventory hits
  for this source path and no selected function/address overlap. Exact audit
  scope, adjacent work and API limitations are in [non-overlap.json](non-overlap.json).

## Reproduce

The repository setup must have materialized the authenticated capture. GNU
objdump/readelf, LLVM objdump and Capstone 5.0.7 are required for regenerating
exports. The verifier uses the retained native text; Capstone qualifies incoming
call sites. Actual versions and commands are recorded in `validation.json`.

```sh
p=research/work-items/RE-001-node115-validator-stake-saturation
python3 "$p/export_disassembly.py"
python3 "$p/verify.py" --controls
python3 "$p/relations.py"
python3 -m unittest discover -s tests -p test_node115_validator_stake_saturation.py -v
make doctor verify test catalogue-check reproduce
shasum -a 256 -c "$p/manifest.sha256"
```

The exporter authenticates the full target before creating a temporary,
byte-identical snapshot for the native disassemblers. It never executes the
capture. The default verification commands compare against committed records;
`--write` is an explicit developer regeneration option. Whole-image, full-body,
export-byte, instruction-span, source, relocation/import and unwind guards are
independently tested.

Validation includes 42 corruption cases with the outer whole-image/body/export
guards bypassed, so an unqualified SHA mismatch cannot masquerade as a semantic
check. Three actual final-CMOV opcode counterfactuals distinguish saturation
from wrapped results on `[MAX,1]` and are rejected by the instruction guards.
The algebra/index corpus checks 2,801 folds, 4,166 wide comparisons, 10,400
flat-span layouts and 124,800 post-lookup branch/address cases. These are static
relation checks, not runs of an emulator, original node or reconstructed Rust.

Before: the base has a checked quorum-policy path but no evidence for these
three functions. After: their complete static bodies, source and helper bindings,
saturation/miss behavior and conditional arithmetic relation are reproducible.
No runtime equivalence or compiler identity is measured. No imported evidence,
source pin, progress gate or shared tool is changed. The root README and
progress image packet counts are regenerated with `make catalogue` (28 to 29). All component
gates remain false. New scripts/docs use root MIT and were independently authored;
no unlicensed inferred source was used.

Next question: establish the two predicate callers' collection provenance and
validity invariants, then close the iterator/lookup and tree traversal contracts
before implementing a complete validator-stakes policy.
