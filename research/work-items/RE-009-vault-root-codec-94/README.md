# RE-009: Which Vault bytes feed a node 94 state-root component?

The low-lane app-hash component captured at state offset `0x8d0` reaches a Vault key/value serializer whose 13-field order, 20-byte address encoding, and map-reader compatibility defaults can now be reconstructed from the selected node 94 bytes.

- Component ID: RE-009 (storage and state roots)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was not copied and is not an authority for these findings.
- Claim status: observations from selected bytes, plus explicitly marked inferences; runtime reachability and full equivalence unresolved.
- Scope included and excluded: selected app-hash input bridge, collector, key and value writers, map reader and selected failure paths. Excludes the complete iterator ordering proof, nested value formats, database keys, all snapshot versions, the other app-hash components, and execution of the node.

## Reproduce

From the repository root with Python 3.12 and the standard library, using the shared section and FDE parsers:

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_vault_root_codec94
python3 tools/vault_root_codec94.py --out work/vault-root-codec-94
for f in evidence.json functions.tsv fields.tsv missing.tsv duplicates.tsv calls.tsv branches.tsv allocation-cases.tsv default-cases.tsv; do
  cmp "work/vault-root-codec-94/$f" "research/work-items/RE-009-vault-root-codec-94/$f"
done
(cd research/work-items/RE-009-vault-root-codec-94 && sha256sum -c MANIFEST.sha256)
```

The tool checks the full input digest before analysis. It reads section and unwind metadata through `tools/elf_index.py` and `tools/fde_extents.py`, excludes `SHT_NOBITS` from byte reads, checks selected FDEs and body hashes, parses the one relevant ELF64 RELA slot, and interprets only fixed x86 byte patterns and relative offsets. It invokes no external programs, does not run the target, and writes nine deterministic files. All VAs below are ELF link-time virtual addresses; ranges are half-open. `functions.tsv` and the windows in `evidence.json` also give file offsets. The analysis is complete only for the selected pins and records, not for every instruction or every caller in the listed bodies. FDE extents are unwind ranges, not a claim that the binary's complete function inventory is known.

## Evidence

### Root bridge and record collection

The existing `research/work-items/RE-009-app-hash-builder-94/closure-rows.tsv` associates low-lane row 7, the previously studied closure `0x28187f0`, and its capture at state `+0x8d0`; its README establishes that those closures serialize their captures before the row hash. The present packet selects no new FDE for that already studied closure. It adds the call-site bytes at `0x2818821..0x2818845` as context: serializer byte `+0xb` is initialized to 1, byte `+0xc` to 0, and the call at `0x2818840` targets the previously uncharacterized bridge `0x25dbd30`. The entry points newly analyzed here have no address matches in the existing work-item evidence.

The bridge calls collector `0x257b7e0` at `0x25dbd9a`, then sequence writer `0x1e45bc0` at `0x25dbda8`. The sequence writer calls pair writer `0x1de2ea0` both for its first selected entry and its loop entries, at `0x1e45c7f` and `0x1e45dae`. The pair writer calls `0x2340f40` or `0x23406d0` for the value, with call sites and error branches in `calls.tsv` and `branches.tsv`. When the context configuration reaches the pair writer unchanged, it takes the branch that emits the two-element pair header; the direct path writes byte `0x92`. On the count path fitting 32 bits, the sequence calls the count-bearing header helper. The iterator's full key ordering and the resulting complete byte stream remain unresolved.

At `0x257b88a..0x257b8b3`, for a selected node base and index `i`, the collector puts two pointers into a 16-byte output record: `base + 0x798 + 20*i` at record offset 0 and `base + 0xb0*i` at offset 8. These are pointer calculations in memory; they are not a claim about a database's on-disk offsets. The 20-byte key interpretation is supported independently by the two key writers, which pass input length 20, output capacity 42, and trim flag 0 to indirect slot `0x5773120`. The generated RELA record binds that slot to `0x29ed380`, the prefixed lowercase hexadecimal helper analyzed in `research/work-items/RE-005-prefixed-hex-rust-94/README.md`; `evidence.json` also records the 16 alphabet bytes. Under that prior helper's normal-domain conditions, the key is `0x` followed by 40 lowercase hex digits, including leading zeroes. This packet does not reanalyze the previously studied helper body.

Before allocating the output pairs, the collector computes the wrapped `count << 4`, checks that the original count has no bits above bit 59, and compares the wrapped size with `0x7ffffffffffffff8`. On failure it calls an indirect error handler; its behavior if that handler returns is not assumed. `allocation-cases.tsv` is a model of those checks, including the last count passing the comparison and the next count. For count zero, the collector sets its length and capacity to zero and uses sentinel pointer `0x8`; after a successful sequence header the empty sequence branches around the pair calls. The collector also has separate bad-iterator and missing-parent branches recorded in `branches.tsv`.

### Value writer

The buffered writer `0x2340f40` reads serializer mode byte `+0xb`; zero selects the 13-element array-header call and nonzero selects the 13-element map-header call. Its named field emissions compare the mode with exactly 1. The direct writer `0x23406d0` reads its mode byte at `+0x1b`; for mode 0 it computes marker `0x9d`, and for mode 1 marker `0x8d`. The mode-1 path emits names. The root context above initializes the mode to 1. For a count fitting 32 bits and with auxiliary byte `+0xc` still zero, the sequence sets a sentinel-backed adapter whose `+0x28` is the original serializer pointer; the pair writer follows the sentinel branch and reloads that pointer for the buffered value call. This is the documented route by which the configured mode reaches the field writer, conditional on intervening helpers succeeding and preserving the configuration. The mode results for values other than 0 and 1 are not generalized here.

The following order and displacements are extracted from `fields.tsv`. These are the actual load or address displacements, not necessarily the start of a Rust field: in particular `name` and `description` load the pointer words inside containers starting at `+0x20` and `+0x38`, respectively. The relationship helper receives the entire object pointer at displacement 0. `is_closed` is loaded as a four-byte word; only its field position is inferred from the matching named writer.

| Order | Name | Input displacement | Required in selected map-reader path |
| --- | --- | --- | --- |
| 0 | `name` | `0x28` | yes |
| 1 | `description` | `0x40` | yes |
| 2 | `create_time` | `0x78` | yes |
| 3 | `vault_user` | `0x84` | yes |
| 4 | `leader` | `0x98` | yes |
| 5 | `user_states` | `0x50` | yes |
| 6 | `leader_commission` | `0x68` | yes |
| 7 | `is_closed` | `0xac` | yes |
| 8 | `lockup_duration` | `0x70` | yes |
| 9 | `allow_deposits` | `0xad` | no |
| 10 | `relationship` | `0x00` | yes |
| 11 | `always_close_on_withdraw` | `0xae` | no |
| 12 | `s` | `0xaf` | no |

The same input displacement occurs in the independently addressed direct writer and in the two selected compiled copies; the generated table records all four input sites. It also records the value call and post-call failure branch for each of the 13 fields in each primary writer. The buffered writer has additional early error joins for field-name writes, as recorded in `branches.tsv`. In the selected `s` value helper, bit 0 chooses the one-byte literal `D` for zero or `U` for one. No claim is made here about the semantic meaning of those letters.

### Reader and compatibility decisions

The separate outer reader `0x1900950` sends its `0x80..0x8f` map-marker branch, with the entry count in the low nibble, to `0x2641c60`. In `0x2641c60`, the selected nonempty-entry loop calls `0x16a54a0` with literal `Address`, checks returned tag 9, copies 20 bytes, and then calls value reader `0x19f9a50`. The address child sets up a 20-byte output region and calls `0x190f5b0`. A failed key result and a failed value result go to separate branches. After insertion, a result discriminator other than 3 branches to a `duplicate key` diagnostic at `0x2642185`; its 13 bytes are reconstructed from the two overlapping immediate stores. This establishes a key/value reader connection. The outer reader map branch and the hash writer sequence-of-pairs have distinct container forms; this packet does not claim they are interchangeable. It also does not establish acceptance of every string the writer can emit or prove all input grammar.

For the selected map route, `missing.tsv` records ten distinct literal `missing field` diagnostics, matching the fields marked required above; `duplicates.tsv` records one `duplicate field` guard and diagnostic for each of the 13 names. At the relevant joins, the three optional slots start with sentinel 2. After successfully reading the required fields, `allow_deposits` resolves sentinel 2 to 1 and otherwise uses its low bit; `always_close_on_withdraw` and `s` use their low bits, resolving sentinel 2 to 0. The resulting bytes are placed in the temporary value at `+0xad`, `+0xae`, and `+0xaf`. `default-cases.tsv` models only slot values 0, 1 and 2. This observation is conditional on the selected map path and on successful preceding child reads, not a claim that arbitrary malformed input is accepted.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No `Cargo.lock`, compiler, linker, build, executable-node capture, target digest fixture, raw binary comparison, relocation closure, or whole-ELF comparison has been produced for this question. The comparisons here are static: selected FDE/body hashes, fixed opcode patterns, direct rel32 edges, a RELA entry, names, displacements, branch destinations and bounded arithmetic models. No normalization masks are applied. The unittest suite includes altered digest, byte, branch, label, slot, relocation and range controls; those are analysis-tool controls rather than proof of target execution.

## Results and limitations

The packet inventories 20 selected FDEs, 13 ordered fields, 13 direct and 13 buffered value failure branches, 13 duplicate diagnostics, 10 missing diagnostics, and three optional default decisions. These are selected-path denominators, not percentages of node functionality. The encoded key is conditional on the cited helper's established normal domain. The identity of the captured component as Vault state is an inference from the matching named writer, address/value layout and its direct call chain. It is not an assertion about database persistence, a snapshot version, uniqueness or sort order of keys, or the entire app hash. No milestone gate is requested.

Next question: determine the collector's exact traversal order and fully characterize the nested `relationship` and `user_states` encodings so that a nonempty row's complete preimage can be independently reconstructed.
