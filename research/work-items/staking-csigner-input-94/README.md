# staking: CSignerAction input through the action handoff in node #94

This packet connects the node's outer action tag `0xb0` to the three signer-action variants and identifies the input and failure branches that must be reconstructed before a jail vote reaches the already studied signer state transition.

- Component ID: staking (validator lifecycle and c-staking signer actions).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not source for this packet.
- Claim status: byte observations and direct control-flow targets below; the interpretations and projections are identified separately.
- Scope included and excluded: the c-signer arm in two outer readers, two c-signer Content readers, their name selectors, and one reader each for the vote map, sequence, and map field. Only selected slices are interpreted or projected. Other outer action arms, actual value parsers, allocation, cleanup, error formatting, and signer state execution are excluded. The labels `inline` and `boxed` distinguish the two observed result carriers; they do not establish a complete allocation model.

## Reproduce

From the repository root, with Python 3.12.3 and the authenticated node artifact present:

```sh
python3 tools/staking_csigner_input94.py --out research/work-items/staking-csigner-input-94
python3 -m unittest tests.test_staking_csigner_input94
(cd research/work-items/staking-csigner-input-94 && sha256sum -c MANIFEST.sha256)
```

The first command overwrites only the generated evidence files. It checks the full artifact SHA-256 before parsing, uses the repository's ELF section and FDE readers, and never runs the node or an external program. Only file-backed sections are mapped. For a determinism check, run the generator into two separate directories with distinct `PYTHONHASHSEED` and `TZ` values, then compare their files byte for byte. The generated file hashes are in `MANIFEST.sha256`; the artifact hash is above. The packet was checked on Linux x86-64. No binutils are used by the generator or tests.

## Evidence

All addresses below are linked ELF virtual addresses. `functions.tsv` contains FDE ranges, FDE and LSDA addresses, and file offsets. An FDE describes an unwind range; it is not proof of a complete semantic function boundary. `windows.json` preserves the actual bytes and SHA-256 of each entire selected FDE and the smaller reviewed windows. `edges.tsv` reports the raw instruction and decoded direct destination for selected calls and branches; it is not a complete CFG. The three tables in `jump-tables.tsv` are decoded directly as 15 signed relative entries apiece.

### Handoff from the outer action

At `0x282ae59` and `0x282d72d`, the respective outer readers call `0x21b1c10` and `0x21b28d0`. Both check the returned status byte and branch to their error path on nonzero. On the zero-status path, each copies 36 bytes from the c-signer reader result beginning at result `+4` into its output at `+8`; the raw instruction operands are in `handoff.tsv`. Each then loads `0xb0` and jumps to a common store of that word at output `+0`. Thus the c-signer result is the payload of outer action tag `0xb0`. The error branches and the two tag stores are independently retained in `edges.tsv` and `windows.json`.

This handoff aligns with the tag and c-signer payload layout in the existing `staking-c-signer-jail-94` packet. That earlier packet supplies the state-transition analysis; this packet does not reanalyse its functions or assert that a decoded action actually reaches execution in a particular external request.

### Envelope, variant, and payload selection

The boxed Content reader begins at `0x21b28d0`. It routes outer Content tags `0x0c` and `0x0d` to direct-key handling and tag `0x15` to a key/value-container path; other tags go to an error arm. On that latter path, a zero entry count or first key tag `0x16` goes to the missing-key arm. With more than one entry, a second key tag other than `0x16` goes to a separate error arm. The `0x16` second-key case is an abstract internal-state control, not evidence that normal encoded input can produce it. The key's 15-entry Content-tag jump table is at `0x3cfa0c`; the inline-reader table is at `0x3cf9d0`.

The generator extracts the compared names from instruction immediates and checks that each extracted memory-byte comparison mismatch reaches the error arm. The bounded interpreters then run the actual name-comparison and branch bytes at `0x219d9e7` and `0x219db67`; they stop at the error arm or the immediate word store. Their accepted cases and instruction traces are in `variants.tsv` and `selector-traces.tsv`:

| Compared bytes | Variant byte | Boxed stored word | Inline stored word |
| --- | ---: | ---: | ---: |
| `unjailSelf` | 0 | `0x0000` | `0x0009` |
| `jailSelf` | 1 | `0x0100` | `0x0109` |
| `voteJail` | 2 | `0x0200` | `0x0209` |

The boxed reader dispatches the resulting variant at `0x21b2e68`. The second bounded interpreter follows the actual comparisons and branches, stopping before cleanup, helper execution, or error formatting. Its `dispatch-cases.tsv` contains the full product of three valid variant bytes, Content tags `0x00` through `0x16`, and abstract lengths 0 and 1:

| Variant | Content value tag | Reached terminal |
| --- | --- | --- |
| 0 or 1 | `0x16` or `0x12` | respective unit arm |
| 0 or 1 | `0x15`, length zero | respective unit arm after cleanup |
| 0 or 1 | any other value, including nonempty `0x15` | respective invalid-value arm |
| 2 | `0x14` | sequence reader at `0x1f4ea40` |
| 2 | `0x15` | map reader at `0x1f24320` |
| 2 | `0x16` | missing-value arm |
| 2 | other | invalid-value arm |

`0x12` is treated as the unit representation, `0x14` as a sequence, `0x15` as a map, and `0x16` as an absence sentinel based on these code paths. These are labels for observed internal Content tags, not a claim about raw JSON or MessagePack byte values. `dispatch-cases.tsv` records dispatch only, so a map or sequence terminal does not mean its contents are valid.

### Vote map and sequence

The map reader calls the field reader at `0x1f244b4`; the latter calls the string helper at `0x21628c9` and `0x21628e5`. The helper's comparison slice is also interpreted directly. It accepts exactly `signer` and `jail_until` as text, storing variant bytes 0 and 1 respectively. `0x2162820` also contains paths for numeric field discriminators 0 and 1; text-only cases must not be generalized to all Content forms. The concatenated field literal and the `CSignerAction::VoteJail` two-element description are retained in `literals.tsv`.

The following map observations concern the success/error status supplied by the omitted field value helpers:

| Condition at the map reader | Observed next path |
| --- | --- |
| Field-key reader fails | error propagation at `0x1f2469a` |
| `signer` already present | duplicate-field arm at `0x1f2476b` before calling the signer value helper again |
| nonzero first word of earlier `jail_until` result | duplicate-field arm at `0x1f24723` before calling the time helper again |
| signer absent when iteration ends | missing `signer` arm at `0x1f24626` |
| signer present but the stored time result's first word is zero | missing `jail_until` arm at `0x1f246be` |
| both present, time word nonzero | construct result, then call cleanup |

The last two rows are deliberately phrased in terms of the helper's first output word. If an otherwise successful time helper can actually return a zero first word, the code treats it as absent and does not mark it as a previous nonzero time for duplicate detection. Whether that helper can return such a value is unresolved; the synthetic zero-word controls do not establish reachability. The missing and duplicate message prefixes are extracted separately in `literals.tsv`.

The sequence reader calls its first element helper at `0x1f4ea57` and its second value helper at `0x1f4eb96`; the latter is also called from the map path at `0x1f24516`. It has distinct first-element failure and absence paths, checks the second element's presence and helper result, and branches to the same missing-second arm if the returned first word is zero. A nonempty remainder branches at `0x1f4ec34` to further length arithmetic and an error or panic path. The exact iterator and helper behavior is not emulated.

On its construction path the map writes variant byte 2 at result `+4`, a 20-byte signer at result `+5`, and a 12-byte time value at result `+0x1c`. The sequence writes the same positions. The outer copy starts at result `+4`, so the tag becomes payload `+0`, the signer payload `+1`, and the time payload `+0x18`. This is the layout needed to relate this reader to the earlier c-signer state-transition packet.

### Projection and inference boundaries

`envelope-projection.tsv`, `map-projection.tsv`, and `sequence-projection.tsv` are synthetic branch projections, not x86 execution of the complete functions. They record actual branch instruction destinations but supply abstract iterator, helper, and cleanup outcomes. In particular, success assumes the omitted helpers and cleanup behave as supplied by the case; the extra-sequence outcome stops before the overflow/error distinction. `dispatch-cases.tsv` and the name traces instead come from bounded instruction interpreters. None is a captured request or execution of the node.

The association of `0xb0` and the reconstructed layout with a c-signer jail/unjail state change is an inference from this handoff, the target literals and the earlier packet. It is not a new independent proof of the state mutation, a wire-format specification, or an assertion that every reader arm has been covered.

## Implementation and comparison

Not yet implemented. No independent Rust component, dependency lock, compiler comparison, raw or normalized binary comparison, relocation closure, or executable target fixture is supplied. The bounded interpreters and branch projections are research tools, not a reconstructed production decoder.

## Results and limitations

- Ten selected FDEs, 23 retained byte windows, 54 direct edges and 45 table entries are recorded; the edge count has the explicitly listed sites as its denominator, not all branches in the functions.
- Eight accepted name traces cover the two copies of the three action names and the two field names. The self-tests additionally try all 17,340 one-byte replacements of those names, plus deletions, appended bytes, bad hashes, corrupted instruction windows, wrong opcodes, invalid addresses and NOBITS mapping.
- The dispatch interpreter has 138 emitted synthetic combinations. The test checks 2,304 combinations across all 256 Content tag bytes, three variants and three lengths. Twelve map, seven sequence and eight envelope cases are projections with stated stubs, not target executions.
- The action reader's other arms, the inline reader's value-handling branches, remaining Content-tag arms, helper implementations, cleanup, panic/unwind behavior, state mutation, and reachability of unusual internal Content states remain open. FDE windows and table targets do not establish instruction coverage or all call sites.
- No progress gate is requested.

Next question: trace the address and time helper outputs on the `voteJail` map and sequence paths, including whether a successful result with a zero first time word is reachable.
