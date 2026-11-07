# Restore candidate path provenance

Partial static evidence for
[issue #3910](https://github.com/lalalune/hyperliquid-source/issues/3910).
This packet resolves the first three words of a 32-byte admitted candidate:
they describe a copied input path. The exact-key result transfers that same
path triple and numeric key. This is path selection evidence, not evidence of
checkpoint bytes being decoded or persisted.

## Artifact and method

Original node #115 ELF: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Owner FDE: `0x25d3f20..0x25d4cab`.

Eight selected windows retain 957 instruction bytes and 218 instructions.
`verify.py` checks the original digest, FDE boundaries, window hashes/rows,
61 explicit field/branch/call/import facts, and 14 semantic corruption
controls. Controls bypass the original/window digest comparisons so changes
to source fields, copy operands, candidate offsets, selection key or imported
copy symbol must fail the corresponding fact checks. Capstone 5.0.7 is used.
No captured code is executed or emulated.

## Producer to selected result

The existing admission loop traverses reversed 24-byte path triples. At
`0x25d423d/4241`, row `+8` and `+16` provide the path pointer and length.
The decimal component parser accumulates its numeric value in `R13`.
Previously mapped filesystem-shaped checks determine whether a row reaches
the copy block. Their IO and path formatting remain outside this packet.

At `0x25d4455`, the code reloads **the original row's full path length**;
`0x25d445e` reloads its original path pointer. For a nonempty path, the
allocation helper receives that length at `0x25d4462/4465`. Its normal
nonnull result is retained in `R12`, passed as copy destination, and the
original pointer and length are passed as source/count to `0x25d4480`.
That call is relocation-bound to the imported `memcpy`. For zero length,
`0x25d4498` chooses pointer value 1 and bypasses allocation/copy.

The append block `0x25d41f7..421e` emits:

| Candidate offset | Source | Meaning under successful normal allocation |
| --- | --- | --- |
| `+0` | `R15` | copied path allocation size/capacity, equal to path length |
| `+8` | `R12` | copied path pointer, or the empty-byte pointer value 1 |
| `+16` | `R15` | copied path length |
| `+24` | `R13` | parsed numeric component |

Appending increments the candidate count and returns to the next 24-byte
input row. A buffer-growth call also returns to the same append block. Thus
the admitted rows preserve the reversed traversal's relative order; the
new 32-byte rows are not newly decoded checkpoint objects.

After nonempty admission, `0x25d459e/45a3/45a8` preserve candidate buffer
capacity, pointer and count in `R12/R15/RBX`. The intervening cleanup retains
those callee-saved values under ordinary helper returns. Group failure takes
a separate sentinel route. The already mapped exact-key scan starts at
`0x25d4955`: candidate `+24` is compared to the original requested key saved
at entry. A matching candidate with a nonsentinel first word reaches
`0x25d4a8d`.

That exit writes the key to output `+24`, transfers candidate pointer/length
to output `+8/+16`, and writes candidate capacity to output `+0`. Cleanup
starts after the selected row, so that transferred path is not freed as a
remaining candidate on this normal exit. This is a move of the copied path
triple, with no second copy or decoding operation at the selected handoff.

## Prior work and overlap

[PR #3819](https://github.com/lalalune/hyperliquid-source/pull/3819) maps reversal,
decimal admission, two filesystem-shaped checks and a 32-byte append whose
first three words were left unresolved.
[PR #3818](https://github.com/lalalune/hyperliquid-source/pull/3818) maps the
exact-key result selection while leaving buffer provenance open.
[PR #3947](https://github.com/lalalune/hyperliquid-source/pull/3947) composes
selection and replay using supplied records. This contribution resolves the
native copied-path provenance; it does not re-claim those earlier stages or
replace the supplied-record implementation.

Terra checked current main, the complete 391-open-PR inventory, relevant
open work, and targeted all-state title/body searches for the producer
instructions and owner. No competing producer-to-result proof was found.
Historical title/body queries do not establish exhaustive inspection of every
unindexed closed patch. The prior reversal/parser/selection facts retained
in this verifier are prerequisites, not additional novelty claims.

## Reproduce and limits

```sh
python3 research/work-items/RE-009-node115-restore-path-provenance/verify.py
```

The repository's audited ELF helper and Capstone 5.0.7 are required.
`verification.json` records successful checks and all 14 rejected controls.
The denominator is only these selected static windows.

Valid input path triples, normal helper returns and successful ordinary
allocation/copy are premises. The zero-length branch is an observed structural
case; this packet does not establish that earlier numeric admission can reach
it. Allocation failures, unwinding, path construction, filesystem IO, decoded
checkpoint contents, persistence, interruption recovery and transaction
rollback are outside scope. #3910 remains open and its component gates remain
false.
