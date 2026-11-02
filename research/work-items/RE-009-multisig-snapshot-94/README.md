# RE-009: multisignature tracker snapshot codecs and duplicate keys

Node #94's `multi_sig_tracker` compact writer can encode each user entry as a two-item address/signers row, while its selected readers recognize three names for the authorized-users field and reject repeated user keys; this gives a reconstruction concrete wire-shape and compatibility decisions for this state subrecord.

- Component ID: `RE-009`, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was a lead only, and no source was copied.
- Claim status: direct observation of authenticated bytes, FDE ranges, literal references, selected calls and branches; bounded inference for the codec and record roles; unresolved for the enclosing persistence entry point and runtime behavior.
- Scope included and excluded: the named outer field and its tracker, row, key and signer writers; compact and JSON-shaped tracker and signer readers; selected field, arity, duplicate-key and error paths; synthetic small examples under explicitly stated modes. Excludes whole-state serialization, actual snapshot-file selection, all input encodings, complete helper internals, tree ordering, threshold business rules, other releases, execution and on-disk compatibility.

## Reproduce

From the repository root on Linux x86-64, using Python 3.12.3 and the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/artifacts.py verify
python3 -m unittest tests.test_multisig_snapshot94
python3 tools/catalogue.py --check
python3 tools/multisig_snapshot94.py --out work/multisig-a
PYTHONHASHSEED=1729 TZ=Pacific/Honolulu python3 tools/multisig_snapshot94.py --out work/multisig-b
diff -r work/multisig-a work/multisig-b
for f in branches.tsv calls.tsv evidence.json field-lengths.tsv fixtures.json functions.tsv; do cmp "work/multisig-a/$f" "research/work-items/RE-009-multisig-snapshot-94/$f" || exit 1; done
(cd research/work-items/RE-009-multisig-snapshot-94 && sha256sum -c MANIFEST.sha256)
```

For a binutils-free check, save the Python executable name before restricting `PATH`, then run the same generator and test module:

```sh
PYTHON_BIN=$(command -v python3)
PATH=work/no-binutils PYTHONHASHSEED=1 TZ=UTC "$PYTHON_BIN" tools/multisig_snapshot94.py --out work/multisig-c
PATH=work/no-binutils "$PYTHON_BIN" -m unittest tests.test_multisig_snapshot94
```

The extractor checks the full input digest before interpreting bytes. It uses the shared ELF section and CIE/FDE parsers, reads file-backed bytes and relocations directly, rejects `SHT_NOBITS` as file-backed data, and validates selected instruction encodings and relative displacements. It writes exactly `evidence.json`, `fixtures.json`, `functions.tsv`, `calls.tsv`, `branches.tsv` and `field-lengths.tsv`; README and manifest are maintained separately. Output contains no time, environment-dependent paths, or external-program output. GNU objdump 2.42 was used only for bounded human inspection. Neither the tool nor the tests invoke it or execute the target.

All addresses are unrelocated ELF virtual addresses, unless a file offset is explicitly labeled. `functions.tsv` records file offsets, FDE and CIE VAs, exact extents with exclusive ends, and full range hashes. Each selected FDE was checked against both the unwind index and the decoded FDE; these are unwind-described ranges, not proof that all source functions or CFG edges have been recovered. The analysis is limited to the listed ranges and instruction windows.

## Evidence

### Outer field and compact write path

The field writer at `0x27b3ab0` references the 17-byte literal `multi_sig_tracker` at `0x3ef524`. In the named-mode arm it then emits a one-field header, references the 25-byte literal `user_to_multi_sig_signers` at `0x3ef1cf`, and calls the row adapter. A separate tracker writer at `0x26ce210` references the same inner literal and calls the same adapter. Their selected call and error-branch bytes are retained in `calls.tsv` and `branches.tsv`.

| Selected role | FDE start | Selected next step |
| --- | --- | --- |
| Outer field / standalone tracker writer | `0x27b3ab0` / `0x26ce210` | Both call `0x25dfa30` |
| Compact row adapter | `0x25dfa30` | Tree collector `0x256df50`, then rows writer `0x1e1eb10` |
| Rows and row writers | `0x1e1eb10`, `0x1dde0d0` | Pair header, key writer `0x1e0d0a0`, signer writer `0x26cdbc0` |
| Signer writer | `0x26cdbc0` | Authorized collection `0x1e15810`, then unsigned threshold writer `0x25ac0d0` |
| Integer helpers | `0x25ac0d0`, `0x25ac580`, `0x25ac7b0`, `0x25ac9e0` | Small integer or 16/32/64-bit payload paths |

The collector visits tree-shaped input and the row writer uses the returned entries. We do not infer an ordering rule. On the selected successful path, the row writer emits an array header of two followed by the key and signer record. The key and authorized-member writers pass input width 20, output capacity 42 and mode 0 to a slot whose ELF relative relocation points to the separately studied formatter. [Prior formatter work](../RE-005-prefixed-hex-rust-94/README.md) establishes `0x` followed by lowercase hexadecimal in this mode; it is a dependency, not a newly claimed function. The authorized collection writer emits an array header. The signer writer emits `authorizedUsers` before `threshold`, and loads the latter as a qword from signer input offset `+0x18`. That offset is an in-memory observation, not a byte offset in a file.

A short human-readable excerpt of the threshold path, with bytes independently retained by the generator:

```text
0x26cdc72  4d 8b 7f 18       load qword at signer input +0x18
0x26cdc7d  48 8d 35 ...      refer to threshold literal
0x26cdca2  e8 29 e4 ed ff    call the unsigned integer writer
```

The standalone tracker and signer writers test serializer byte `+0xb`: zero chooses an array header and one chooses a map header with field names. Other values are deliberately excluded: the code separately tests nonzero and equality to one. A row-writer branch also tests a byte at `+0xc`; the examples below assume it is zero, so the ordinary two-element header is written. Failure at the field name, collection, key, signer, or threshold helper propagates through a distinct selected return path; no claim is made about I/O atomicity.

The integer writer's `<256`, `<65536`, and upper-32-bit decisions, marker stores, and byte-order instructions give the following *static models* after successful writes. Full boundary cases are in `fixtures.json`.

| Threshold input | Encoded hex |
| ---: | --- |
| 127 | `7f` |
| 128 | `cc80` |
| 255 | `ccff` |
| 256 | `cd0100` |
| 65535 | `cdffff` |
| 65536 | `ce00010000` |
| 4294967296 | `cf0000000100000000` |

### Compact read path and field decisions

The tracker reader `0x1716c90` has a map arm and a sequence arm, both of which call the row reader `0x1901890`. Its two overlapping 16-byte comparisons plus the length check identify the same 25-byte tracker name. For the selected map and short-array markers, the row reader chooses native-map reader `0x263c0f0` or pair-array reader `0x266f210`. The latter calls pair reader `0x170f470`; both routes reach signer reader `0x18325a0`. The native-map arm passes the four-byte literal `User` to its key decoder at `0x1699080`; the pair reader supplies a 20-byte key buffer and calls `0x190f5b0`. The latter is a contextual shared callee, also named in [prior staking wire work](../staking-action-wire-94/path.tsv), not a newly claimed FDE. The signer reader calls the same authorized-collection and threshold child readers from its map and sequence arms; their complete grammars are not analyzed here. This is a bounded marker-path claim, not an exhaustive marker grammar.

Compact signer classifier `0x26bfe00` and JSON signer classifier `0x26bfea0` each use a 15-entry signed-relative length table and compare bytes as follows; the exact table bytes and VAs are in `evidence.json` and the compact destinations are also in `field-lengths.tsv`.

| Field bytes | Length | Classifier tag | Writer's named form |
| --- | ---: | ---: | --- |
| `au` | 2 | 0 | No |
| `authorizedUsers` | 15 | 0 | Yes |
| `authorized_users` | 16 | 0 | No |
| `threshold` | 9 | 1 | Yes |
| Other names | other or mismatched | 2 | No |

The selected signer map arm tracks presence by tag. After successful child and unknown-value reads, completion requires tags 0 and 1; a second occurrence of either recognized tag takes its duplicate-field route. Thus two different authorized aliases count as duplicates of the same field. An unknown name takes a separate helper path; arbitrary unknown values and helper failures are not modeled. The tracker reader similarly has distinct missing and duplicate recognized-field routes.

The error paths also assemble a field-name slice and refer to length-prefixed diagnostic templates. The following selected name references and template references are decoded directly from RIP-relative operands; `evidence.json` retains each instruction, length immediate, target address and template-prefix bytes. The compact missing and duplicate arms refer to different template prefixes. The JSON duplicate arms refer to the same duplicate prefix. This connects presence decisions to the diagnostic data without asserting the complete formatted error message.

| Reader and failure | Name-reference VA | Template-reference VA |
| --- | --- | --- |
| Compact tracker, missing | `0x17177c7` | `0x17177fa` |
| Compact tracker, duplicate | `0x1717e6d` | `0x1717e95` |
| Compact authorized users, missing | `0x18329aa` | `0x18329ea` |
| Compact threshold, missing | `0x1832a45` | `0x1832a7f` |
| Compact authorized users, duplicate | `0x1833eb1` | `0x1833eee` |
| Compact threshold, duplicate | `0x1833f27` | `0x1833f64` |
| JSON tracker, duplicate | `0x1beef67` | `0x1beef91` |
| JSON authorized users, duplicate | `0x1c0fdd4` | `0x1c0fe02` |
| JSON threshold, duplicate | `0x1c0fd84` | `0x1c0fdb2` |

The selected short-array decisions below apply only after preceding child reads succeed. A child error can take precedence over the indicated count outcome.

| Record | Count 0 | Count 1 | Count 2 | Greater than expected |
| --- | --- | --- | --- | --- |
| Tracker | Missing first | Join | Extra element | Extra element |
| User/signers row | Missing first | Missing second | Join | Extra element |
| Signers | Missing first | Missing second | Join | Extra element |

The actual branch targets and the tested count 0 through expected-plus-one cases appear in `branches.tsv` and `fixtures.json`. These tables do not imply that an array with the stated count and malformed children succeeds.

### Duplicate keys and JSON-shaped path

The compact native-map and pair-array readers and the JSON row reader call insertion routine `0x2860580`. At `0x2860608` a call through dynamic slot `0x576e488` resolves in the ELF to the imported symbol `memcmp`; its length argument is 20. On comparison result zero, branch `0x286062f` reaches the existing-key arm, which copies the previous 32-byte value out, replaces it with the new value and returns tag 1. All three selected reader paths test that tag and construct the bytes `duplicate key`. The in-progress in-memory replacement is observed before each reader's error handling; no conclusion about persisted state or transactional rollback follows. Dynamic interposition and actual runtime behavior were not tested.

The JSON-shaped writer path `0x26cdfb0` -> `0x25df550` -> `0x291b5c0` -> `0x26cdd10` references the same field names, emits bracket bytes around the collection and rows, and calls the signer-value writer. The selected reader path is `0x1bee850` -> `0x261ff40` -> `0x1b748a0` -> `0x1c0f280`; its signer classifier is the second table above. These selected paths support corresponding field roles, not a claim that every JSON input or output form matches the compact grammar.

### Synthetic examples and inferences

The following examples encode the tracker subrecord alone, without the enclosing `multi_sig_tracker` key. They are constructed from selected instruction constants and the prior formatter result, assuming successful helpers, mode byte `+0xb` equal to 0 or 1, mode byte `+0xc` equal to 0, and already ordered unique input rows. They are not captured output and do not demonstrate which configuration a real snapshot uses.

| Model | Hex |
| --- | --- |
| Empty named tracker | `81b9757365725f746f5f6d756c74695f7369675f7369676e65727390` |
| Empty positional tracker | `9190` |

`fixtures.json` also records a single-row example with synthetic 20-byte key `00..13`, authorized member `14..27`, and threshold 1, in both modes. A small independent test parser checks the example's nested structure. Neither that parser nor the Python field-presence model invokes or independently validates the native reader.

The literal names and linked calls support interpreting the selected record as the multi-signature tracker state subrecord. A direct connection from this particular writer to a particular persisted snapshot file, the format used in production, and compatibility across releases remain unresolved.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler/linker flags, reproducible builds, native byte comparison, normalization masks, complete helper/relocation closure and target execution: not yet measured. The only target input is the authenticated ELF; synthetic fixture inputs and their assumptions are explicit above. No reference source is copied into an implementation.

The 17 focused unittest methods check target digest, selected FDE extents and body hashes, branch and call decoding, field tables, aliases, modeled boundary values and fixtures. Negative controls cover a changed digest, a changed body byte, an altered FDE extent, invalid and out-of-range addresses including NOBITS, bad call and branch opcodes/displacements, modified relocation and dynamic-symbol entries, a modified table entry, a modified field name and a modified diagnostic-template prefix. Both signer classifiers are checked against 21,420 one-byte substitutions in total, and the tracker name against 6,375. The substitutions test the extracted static classifier model; they do not execute node code. The independent fixture parser rejects truncation, a reserved marker and trailing bytes.

## Results and limitations

The deterministic extractor records **30 selected FDE-described ranges, 60 direct call sites, 56 conditional branch sites, 75 pinned windows, 8 named-field references, 9 field-diagnostic references and 2 fifteen-entry classifier tables**. These are selected evidence counts, not whole-node coverage. Six generated files were regenerated identically with different hash seeds and time zones, including with binutils absent from `PATH`. Seventeen focused tests passed without skips; artifact verification and catalogue checks passed. No full-scope progress gate is requested.

The exact on-disk snapshot context, full reader and helper grammars, sorting of nonempty collections, writer configurations outside the two modeled values, business validation of threshold versus member count, error precedence beyond the selected arms, and behavior of an actual node remain open. Next question: identify a non-overlapping snapshot entry point that supplies this tracker and establish its actual serializer configuration with an authorized offline fixture.
