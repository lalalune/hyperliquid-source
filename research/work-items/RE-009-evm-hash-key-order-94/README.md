# RE-009: node94 local block-hash key search and equal replacement

The local search in `0x28546c0` compares four unsigned 64-bit words in offset
order `24, 16, 8, 0`. A greater candidate scans the next slot in the current
node; a lesser candidate selects a child edge. Equality copies out the old
32-byte associated value, stores the new value and returns tag 1. These
observations resolve the local key relation and replacement path without
establishing global collection or serialization order.

- Component: RE-009 / storage and snapshots.
- Target: Linux x86-64 node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes,
  SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source revision: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference revision: not used. No inferred reference implementation was copied.
- Status: instruction, call and memory-transfer observations; mathematical
  interpretation for the unsigned 256-bit relation; global tree invariants,
  nominal source types and runtime behavior remain unresolved.
- Scope: one 624-byte FDE-described extent `0x28546c0..0x2854930` and a credited
  contextual call edge. No component gate is advanced.

## Overlap check

The check used live PR metadata, exact changed-file lists and exact head files.
Upstream main was `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The unsubmitted
`RE-009-evm-block-hash-row-94` packet remains preserved at its existing base
`3324e50333042b391312515e542279ca21f63dc8`; its selected row-shape claim should
be retired as a submission candidate because it overlaps #1379.

| Prior work / checked head | Established or proposed scope | Relationship to this packet |
| --- | --- | --- |
| [#1291](https://github.com/lalalune/hyperliquid-source/pull/1291), merged, `d1bb9bb07c236f89425b776ced79fea634fdbb0c` | `RE-009-evm-state-wire-94`, `tools/evm_state_wire94.py`, `tests/test_evm_state_wire94.py`; outer placeholder, field labels, empty collector and outer readers | Existing context; no new claim for these bodies |
| [#1379](https://github.com/lalalune/hyperliquid-source/pull/1379), open, `85ba708aab7a44a2f35692ecd99dd3b072d19acd` | `RE-009-evm-hash-key-94`, `tools/evm_hash_key94.py`, `tests/test_evm_hash_key94.py`; selected compact row, both byte transforms and selected readers; observes insertion return 1 | Credited reader call context only. Its 14 selected FDEs exclude `0x28546c0`; local comparison and replacement internals are new here |
| [#1384](https://github.com/lalalune/hyperliquid-source/pull/1384), open, `b5aeb1024a2ddfe885b7deaf4c75aabe5e55662b` | `RE-009-evm-hash-json-94`, `tools/evm_hash_json94.py`, `tests/test_evm_hash_json94.py`; JSON rows and item adapters | Its 20 selected FDEs exclude `0x28546c0`; no JSON claim is repeated |
| Preserved `RE-009-evm-block-hash-row-94` | Includes the selected binary row, pointer collector, the same insertion body and limited uniqueness observation | Preserved without edits. This new question is the exact word priority, unsigned relation, local search direction and equal-value transfers, rather than its row codec |

Live searches for RE-009, `block_hashes`, `28546c0` and key-order wording found
no other PR claiming this local comparator. A search result is not an ownership
guarantee; recheck current GitHub before submission. Existing PR tests and
generators were read for overlap, not run or adopted as implementation.
The refreshed intake also checked #1417 at
`1b45aefea4dbfc29b94d30608addedc792b8e1f5` (HIP3 nested four-field codec) and
#1410 at `b9f2822b5bff7496127e4103a3a8ae37a4e737a6` (lattice quoted/array
scanner). Their full bodies/diffs contain no claim for `0x28546c0` or its local
comparison/replacement sites; main remained `56c0ec67`.

## Evidence

Addresses are linked ELF virtual addresses, with exclusive extent ends.
`evidence.json` retains the complete 624-byte primary body, its SHA-256,
file offset, indexed FDE/CIE bytes, decoded contract and 22 selected control
transfers. `native.asm` retains the complete GNU disassembly of that extent
with line-end whitespace removed; the verifier rebinds every exported raw
byte. An unwind range does not prove
the original function boundary or absence of split cold code.

The credited call context `0x269fd9c..0x269fdc6` is checked byte for byte. At
`0x269fda4`, RDX receives `rsp+0xb0`; at `0x269fdac`, RCX receives `rsp+0x90`.
The direct call at `0x269fdb4` resolves to `0x28546c0`. RDI is R12 and RSI is
`rsp+0x8`. This binds the exact caller/callee and argument setup. The
collection-reader and row-buffer interpretation belong to #1379 and are
context only, excluded from the new primary extent and byte counts. Its
following status check and duplicate error are credited observations; this
packet does not establish persistent mutation on a failed snapshot read.

| Native sites | Observation |
| --- | --- |
| `0x28546e4..0x28546f3` | Candidate qwords are loaded from RDX offsets 24, 16, 0 and 8 into registers |
| `0x2854730..0x2854763` | Stored-key qwords at slot offsets 24, 16, 8 and 0 are compared to their corresponding candidate registers; the first mismatch jumps to `0x2854710` |
| `0x2854710..0x285471b` | `cmp rbp,r13; seta bpl; sbb bpl,0` computes 1 for unsigned greater and -1 for unsigned less, preserving the CMP borrow through SETA |
| `0x285471b..0x2854728` | Advances the slot offset by 32; a relation of 1 continues scanning in the current node |
| `0x2854770..0x2854796` | A negative mismatch reaches child selection at `0x2854783`; the child pointer comes from node+`0x2d0+8*index`. Exhausted height reaches `0x28547e1` |
| `0x2854796..0x28547b0` | Equal keys load old value halves from node+slot+`0x160` and `0x170`, then store them at result+1 and +17 |
| `0x28547b0..0x28547d0` | Loads new halves from RCX+0 and +16, stores at the same two value offsets, sets AL=1 and jumps to `0x28548f0` |
| `0x28548ea..0x2854907` | Equality skips the visible container-length increment at `0x28548ea`; the join stores AL at result+0 and returns the result pointer |

For the authenticated instructions, comparing these four little-endian words
from highest to lowest is the mathematical relation on an unsigned 256-bit
integer. The exact source type is not recovered. The stored-key slot uses a
32-byte stride, separate from the associated-value area at `+0x160`.
No sorted-node invariant or global iterator sequence is proved by that local
search. The equal path contains no call; its memory-transfer interpretation
assumes valid pointers and the ordinary nonaliasing layout. Arbitrary aliases,
invalid trees, concurrent mutation and unwind behavior are outside this result.

The nonempty miss path calls `0x1ab3d20` at `0x2854859`; that insertion helper
is unresolved. The three indirect call slots are `0x576dfd8`, `0x576e020` and
`0x576e108`; no allocator or error-helper equivalence is claimed. They are
retained as call-closure gaps, not replaced with stubs.

## Reproduce

Run from the repository root with Python 3.12.14, GNU binutils 2.44, Git
2.52.0, git-lfs 3.6.1 and GnuPG 2.4.7. `PLAN.json` was fixed before writing
the verifier. The standard-library verifier uses the repository's ELF/unwind
parsers and invokes no subprocess or captured instruction evaluator.

```sh
python3 -I -B research/work-items/RE-009-evm-hash-key-order-94/verify.py
python3 -I -B -m unittest discover -s tests -p test_evm_hash_key_order94.py -v
python3 -O -B -m unittest discover -s tests -p test_evm_hash_key_order94.py -v
python3 -I -B research/work-items/RE-009-evm-hash-key-order-94/verify.py --out /tmp/re009-key-order-first
cmp /tmp/re009-key-order-first/evidence.json research/work-items/RE-009-evm-hash-key-order-94/evidence.json
(cd research/work-items/RE-009-evm-hash-key-order-94 && sha256sum -c MANIFEST.sha256)
make doctor verify catalogue-check reproduce
```

The local worktree materializes the superproject's pinned LFS identities and
seven pinned source checkouts from existing authenticated local inputs.
`make verify` initially reported a modified LFS source in the clone with no
inherited LFS filters. It passed with only these standard invocation-local
settings; no checker or persistent Git configuration was changed:

```sh
GIT_CONFIG_COUNT=3 \
GIT_CONFIG_KEY_0=filter.lfs.clean GIT_CONFIG_VALUE_0='git-lfs clean -- %f' \
GIT_CONFIG_KEY_1=filter.lfs.smudge GIT_CONFIG_VALUE_1='git-lfs smudge -- %f' \
GIT_CONFIG_KEY_2=filter.lfs.process GIT_CONFIG_VALUE_2='git-lfs filter-process' \
make verify
```

## Implementation and comparison

Independent Rust, Cargo.lock, compiler/linker flags, rebuilt code comparison,
normalization masks and runtime fixtures: not implemented or measured. The
Python relation is a bounded mathematical interpretation of decoded fields,
not a tree implementation, codec or instruction emulator. The tests compare
it to independent whole-integer arithmetic on 2,842 synthetic pairs: every
deciding word, sign-bit boundaries, all 256 one-bit positions, equality and
2,048 deterministic random pairs. These counts are oracle cases, not target
execution or a component-coverage denominator.

Seven predeclared native mutations change candidate/stored offsets, SETA,
a mismatch destination, two replacement addresses or the equal tag. Each is
decoded below the identity boundary and rejected as a changed contract. Two
mutations also produce an explicit mathematical counterexample. Changing
SETA to SETG while retaining SBB combines signed greater with unsigned borrow;
it is not modeled as an ordinary signed comparator. Further controls reject
changed widths/opcodes, wrong file identity, invalid key lengths, missing or
ambiguous/NOBITS virtual ranges, changed/incomplete raw exports and incomplete,
duplicate or corrupted manifest entries.

## Results and limitations

The 11 focused unittest methods pass normally and with Python `-O` (exit 0
each). Two exports under different hash seeds and time zones compare byte for
byte with each other and the committed evidence (exit 0). `make doctor verify
catalogue-check` passes (exit 0), authenticating all three targets and 38
imported files plus the seven source pins. `make reproduce` passes (exit 0).
The packet verifier and scoped manifest checks pass (exit 0). Actual local logs
are `/tmp/re009-key-order-required.log` and
`/tmp/re009-key-order-reproduce.log`; they are transient environment records.
The doctor recognizes LLVM 19.1.7 through the explicit existing executable
`/workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump`; Ghidra and both
rebuild toolchains remain unavailable in this tree, which the static verifier
does not require. The full repository `make test` gate is deferred to the
coordinator's single integration run; this packet does not claim it passed.
Captured execution opt-in flags remain unset. No node, visor or captured
instruction execution occurred. Hosted CI and containers were not tested.

This packet establishes one local comparison/replacement contract. It leaves
global row order, insertion rebalancing, complete duplicate/error semantics,
production serializer/deserializer modes, source ownership and nominal types,
actual disk compatibility and other releases open. No acceptance gate changes.
The next question is to trace the unresolved insertion helper and establish
the tree invariants needed before relating this local comparison to iterator
order.
