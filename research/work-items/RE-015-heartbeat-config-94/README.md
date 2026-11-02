# RE-015: heartbeat configuration initialization from the global directory

The node #94 bytes connect the global configuration directory to a heartbeat-jailing tracker whose two JSON fields have independent defaults and duplicate-field errors, providing a concrete initialization and failure contract for a future reconstruction.

- Component ID: `constants` / RE-015, with a bounded consumer in the node heartbeat tracker.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` is an unlicensed, inferred lead and is not copied.
- Claim status: static observations and explicitly marked inferences; no node execution or component gate.
- Scope included and excluded: 15 selected, previously unowned #94 FDE extents; fixed instruction patterns, specified relocation slots, this constructor's formatting, read/default/write selection, JSON field dispatch, error exits and seed-map insertion. The earlier configuration initializer, general file helpers, general number scanner, general unknown-value skipper, existing-file reader, post-initialization tracker update, #115 and visor are boundaries. The old 76-name table is not resubmitted.

## Reproduce

Run from the repository root on Linux with Python 3.12.3 and the authenticated artifacts available. The producer uses the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; it does not invoke binutils or the target. It first checks the full target size and SHA-256. It reads only the binary and writes the listed evidence files in the requested output directory. Replace the placeholders with two distinct writable directories:

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_config_heartbeat94 -v
PYTHONHASHSEED=1 TZ=UTC python3 tools/config_heartbeat94.py --out <tmp-dir-a>
PYTHONHASHSEED=987 TZ=Pacific/Honolulu python3 tools/config_heartbeat94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
python3 tools/config_heartbeat94.py --out research/work-items/RE-015-heartbeat-config-94
(cd research/work-items/RE-015-heartbeat-config-94 && sha256sum -c MANIFEST.sha256)
```

The committed `MANIFEST.sha256` gives the output hashes for the generated files and this README. The two comparison directories must initially be empty: the producer replaces its own files but does not delete unrelated files. The two hash-seed/timezone runs were also made with a `PATH` containing Python but no binutils. Artifact verification, catalogue check, and a separate inventory/literal reproduction passed. The import verifier passed with a writable temporary Git LFS storage setting; its default Git LFS storage was read-only in the analysis environment. No full repository test suite was run.

## Evidence

All addresses below are linked ELF virtual addresses (VAs); `functions.tsv`, `instructions.tsv`, `edges.tsv`, and `contracts.tsv` also give file offsets. End addresses are exclusive unwind FDE extents, not independently established complete source-function boundaries. The body hashes, sections, relocations, FDE/LSDA fields and instruction bytes are read from the authenticated ELF, not from a disassembler's output. Names are roles assigned for this packet.

| Role | Selected FDE VA range |
| --- | --- |
| JSON document wrapper | `0x43a33b0..0x43a34c5` |
| JSON error builder | `0x43a3de0..0x43a3e98` |
| JSON sequence first-element wrapper | `0x43a6aa0..0x43a6c02` |
| JSON numeric dispatch | `0x43a9250..0x43a93b7` |
| JSON boolean parser | `0x43aa8d0..0x43aaaa9` |
| Two-field JSON parser | `0x43ae9c0..0x43af1ff` |
| Constructor failure cleanup | `0x4732600..0x47326a3` |
| Initial row population | `0x474e220..0x474e50e` |
| Tracker constructor, scope entry | `0x474ece0..0x474f8a0` |
| Binary configuration encoder | `0x474ff60..0x475014e` |
| Seed-map insertion | `0x4938330..0x493864c` |
| JSON float-field writer | `0x4a806e0..0x4a8085a` |
| JSON boolean-field writer | `0x4a99530..0x4a99653` |
| JSON key writer | `0x4ab04c0..0x4ab06ad` |
| Binary float writer | `0x4aeafc0..0x4aeb161` |

The older `constants` and `RE-001-build-mode-94` packets relate the configuration initializer to the `cham` and `static_config` suffix leads, the `NvTestnet` default, and the directory-like field labelled `cham_dir`. They do not establish this consumer. Here the constructor's instruction at `0x474edee` reads slot `0x576e928`, whose ELF relative relocation has addend `0x577b288`; it checks the cell word at `+0x50` and passes cell `+0x18` as a format argument. The relocation on the cell points to the previously owned initializer. The string adapter named at `0x4774750` is an external boundary: an earlier work item's caller disassembly already refers to it, so its FDE is not selected here.

The format-template bytes at `0x1ee03e`, its three argument descriptors, and the relocation from descriptor `0x572ed38` to the 24 bytes `heartbeat_jailing_config` are in `path.json`, `contracts.tsv`, `edges.tsv`, and `relocations.tsv`. The second argument has length zero. **Inference:** using the previously established formatter convention and directory-field attribution, the result is `CONFIG_DIR` followed by the relative suffix `file_mod_time_tracker/heartbeat_jailing_config.json`. The runtime directory bytes and any filesystem normalization are unknown. Under that formatting inference the suffix alone is 52 bytes and ends in `.json`; the special nine-byte bypass and `rmp`-extension encoder branch in the generic code are therefore not asserted to be feasible for this concrete formatted result.

### Constructor branches and failure boundaries

| Condition and site | Observed next step |
| --- | --- |
| Regular-file predicate at `0x474eea1` returns nonzero | Obtain metadata through slot `0x576e9f0`; metadata tag 1 reaches the fallback, otherwise call existing reader `0x4721bb0`. |
| Existing reader returns byte tag 2 at `0x474f1df` | Prepare the diagnostic `could not load file, using default value. Error: `, retain an error-shaped word, and continue with defaults. The metadata-tag-1 route joins the same fallback. |
| Existing reader returns another tag | Retain the returned float and byte with metadata-shaped words; full ABI and actual I/O results are not established. |
| Predicate returns zero | Start with the default fields, compare a nine-byte special path encoded as `2f6465762f6e756c6c`, then call extension predicate slot `0x576f620` for other paths. Zero chooses the JSON writer; nonzero chooses the binary writer. A zero predicate is not proof that the path is absent. |
| Serialization returns an error | The JSON and binary paths have separate error conversion and cleanup, before the common unwrap diagnostic at `0x474f737`. |
| First file step at slot `0x576ea68` returns nonzero | Skip the second step and reach the unwrap diagnostic after buffer cleanup. |
| Second file step at slot `0x576f670` returns nonzero | Reach the same unwrap diagnostic; success continues with defaults. |
| Time conversion or allocation fails | Separate diagnostic/allocation branches are present; the exception call-site tables and cleanup entry are retained without asserting all callee behavior. |

The prior `bridge-state-json-94` packet identifies the extension predicate as case-folded `rmp` selection and describes the two file-step slots as boundaries. This packet records the call sites and return tests, not a claim that a file was actually read or written. The encoder's named-mode and positional-mode branch are both retained because they are present in the FDE; the concrete setup passes named mode. The old marker helper `0x4aed5a0` is covered by `stream-msg-codecs-94`, which reports that marker values in the relevant range pass unchanged.

### JSON representation and read-side decisions

`RE-008-auto-jail-vote-94` follows the later tracker update but leaves its existing-file reader as a stub; this packet follows the previously unowned JSON descendants of that boundary. One boundary call at `0x4721f97` targets the new document wrapper; its bytes and relative operand are in `contracts.tsv` and `edges.tsv`, but the old FDE is not a selected body. The wrapper calls `0x43ae9c0`; after a non-error result it scans trailing whitespace and uses error code `0x16` for another byte. The four bytes admitted by the repeated whitespace mask are 9, 10, 13 and 32 (`json-whitespace.tsv`). The object parser compares exact decoded key bytes and length: `dry_run` (7) and `latency_ema_jail_threshold` (26). `key-windows.tsv` and `key_layout.json` derive the input displacements, constant bytes and coverage from the selected instructions. The first four and last four bytes of the seven-byte key overlap; the two 16-byte comparisons of the 26-byte key overlap by six bytes, covering every byte.

| Object condition | Static observation |
| --- | --- |
| `dry_run` absent | On object close, the sentinel selects byte 1. |
| `latency_ema_jail_threshold` absent | On object close, the absent flag selects binary64 bits `0x3fc3333333333333`, approximately 0.15. |
| Either known field repeated | Its own seen-state check takes a duplicate error branch before parsing the second value. |
| Other decoded key | Its value is passed to the separate skip helper; the object continues only if that helper reports success. |
| Boolean value | The selected boolean reader checks the lowercase `true` and `false` bytes, with distinct end-of-input and mismatch branches. The enclosing parser still checks delimiters. |
| Numeric value | The selected dispatcher accepts a leading minus or decimal digit into an external numeric scanner, branches on its result, and converts returned representations to binary64. The scanner's full grammar and rounding are not closed here. |
| Opening sequence delimiter | The parser takes a separate sequence path and calls the first-element boolean wrapper, then has a numeric dispatch and default paths. Its complete malformed-sequence grammar remains open. |

The JSON writer uses the same two field names, the common key writer, two-space indentation, and lowercase boolean literals. The float writer masks the sign bit and compares the magnitude to the infinity representation; a nonfinite magnitude uses the bytes for `null`, while finite formatting is delegated. The binary float writer emits marker `0xcb` and the eight IEEE-754 bits in big-endian order. These are observations of writers, not a round-trip or exact finite-number-text claim.

The focused tests use synthetic key mutations and float-boundary inputs against the extracted comparison windows and constants; those inputs are controls, not captured target runs. `branches.tsv` records taken and fallthrough addresses; `cfg.tsv` is a graph overapproximation that assumes calls return and ignores condition feasibility. It is not runtime coverage.

### Published state and reference comparison

`output-stores.tsv` records the temporary destination offsets preceding the checked 352-byte copy. At offsets `+0xb0`, `+0xb8`, and `+0xc0` are the path-shaped three words; `+0xc8` is the selected float and `+0xd0` the selected byte. Offset `+0xd8` receives bits `0x4014000000000000` (5.0); `+0xf0`, `+0xf8`, and `+0xfc` receive error- and metadata-shaped words. Units and complete types are unresolved. The fallback's float comes independently from the data constant at `0x20a308`; it matches the immediate in the default writer and the JSON absent-field path.

The constructor calls `0x474e220` before copying out the result. Its input root and count both gate iteration. For each 20-byte key it prepares a 104-byte row, including binary64 bits `0x4066800000000000` (180.0) at row offset `+0x20`, then calls `0x4938330`. The selected insertion helper compares 20 bytes; an equal key takes the replacement path. An empty root allocates 1,376 bytes, checks a count against 11 and stores the row; the nonempty insertion/split helper is an external boundary. Neither 180.0's unit nor the full map ABI is inferred.

The reference's `node/startup.rs` names `heartbeat_jailing_config`, which agrees with the linked binary descriptor; that source-level name by itself does not supply the directory, field defaults, branch behavior or layout established here. Its `global_constants/static_config.rs` names `cham_dir` and `NvTestnet`, both previously investigated leads, not proof of the live runtime directory or network. No illustrative reference default is substituted for the binary-immediate values.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler and linker settings, two-build results, raw/normalized byte comparison, masks, dynamic call-target closure, vtable/data closure and whole-ELF comparison: not yet implemented/measured. This packet supplies static evidence and synthetic controls only. The fixed byte contracts are corruption guards, not equivalent target executions or independent Rust behavior tests.

## Results and limitations

The chosen ranges total 10,548 bytes in 15 FDE records. The restricted byte-pattern reader partitions them into 2,409 instructions and records 564 control transfers, of which 263 are conditional. It records 41 fixed byte contracts, 41 selected edges (including the one prior-owned boundary call), 55 named branch decisions, six LSDA tables with 56 bounded call-site records, and 23 structural reachability queries. These counts describe only this selected set, not a complete function census or matched-window denominator. The machine-readable records include all selected bytes and raw relocation records; unwind action meanings are not decoded.

The focused suite passed 26 tests with no skips, including altered artifact hash and bytes, malformed ranges, overlapping or NOBITS mappings, changed opcode/relative branch, duplicate FDE or relocation, malformed LSDA, a one-bit mutation at each field-name byte, boolean literal bytes, nonfinite boundaries and distinct failure routes. The full component remains 0/4; no gate is requested. Actual formatter semantics across all inputs, I/O, numeric conversion edge cases, unknown-value skipping, unwinding behavior, dynamic use of the tracker, and cross-release equivalence remain unresolved.

Next question: close the numeric scanner and the existing-file reader's error and ownership contracts against independent inputs, then compare an independently implemented initializer without treating these static checks as an execution oracle.
