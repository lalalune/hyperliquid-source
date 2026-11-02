# RE-015: configuration-rooted database home selection and two-record publication

Node #94 selects two distinct configuration-rooted database-home suffixes using adjacent 64-bit sentinels, preserves an explicit input path for other values, and passes a two-key range into a map-construction route; a reconstruction can preserve these choices and their failure cleanup without inventing a concrete global directory.

- Component ID: `constants`, RE-015 (`global_constants/*`), with a bounded downstream storage consumer. The descriptive names below do not claim symbol or source-file ownership.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; inferred, unlicensed `can1357-hl` reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a lead only; this packet copies no reference implementation.
- Claim status: observations are the selected raw bytes, linked targets, relocations, FDE and exception-table records. Path rendering, record/container roles and the two-record transfer model are inferences. Concrete runtime inputs, external helper behavior and whole-component coverage remain unresolved.
- Scope included and excluded: eight previously unclaimed #94 FDE extents, two complete suffix entries and an argument-only entry, the selected caller-to-output route, local failure cleanup, and the two-record insertion case. The earlier static-config initializer, formatter, directory-guard collector, allocation routines, external destructor and generic large-tree split are boundaries. Node #115 and visor are separate targets. No component gate is requested.

## Reproduce

Run from the repository root with the pinned input present. The collector uses the Python standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. It checks the complete input size and digest before parsing, rejects ambiguous or non-file-backed mappings, and invokes no external program. It uses fixed patterns at reviewed instruction starts, not an x86 instruction census. No captured executable is run.

```sh
python3 tools/config_db_roots94.py --out research/work-items/RE-015-db-home-branches-94
python3 -m unittest tests.test_config_db_roots94 -v
python3 tools/doctor.py
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-db-home-branches-94 && sha256sum -c MANIFEST.sha256)
```

For independent regeneration, replace both placeholders with distinct empty writable directories:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_db_roots94.py --out <out-a>
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/config_db_roots94.py --out <out-b>
diff -r <out-a> <out-b>
```

Environment used: Linux x86-64, Python 3.12.3 and GNU objdump 2.42. Objdump was used only for bounded human inspection, never as generator or test input. For example, the selector can be inspected with:

```sh
objdump -d --start-address=0x15861d0 --stop-address=0x1586308 artifacts/node/94/hl-node
```

The producer SHA-256 is `0142bf223e2ef7995b14febfd7221fd251acc1353f18d8e548c07f1c9ed45723`; the focused test SHA-256 is `ca0e72ed25a7e328fbbf2437453835ba83b397fb00cd4f18bb5a300eac755ab7`.

`evidence.json` records eight FDEs with their complete bytes and body hashes, 11 selected RELATIVE relocations, three entries, five exception-table headers and explicitly identified abstract models. `windows.tsv` contains 46 fixed raw-byte windows, `transfers.tsv` 43 selected direct-transfer encodings, `rip-references.tsv` 26 selected RIP operands, and `exceptions.tsv` all 29 decoded entries in the five selected call-site tables. `MANIFEST.sha256` covers these files and this README. Encoded exception actions are retained as integers; action chains, personality behavior and reachability are not inferred from the table alone.

## Evidence

Addresses below are linked ELF virtual addresses. The machine-readable files also give source file offsets. FDE ranges are unwind-described extents, not a complete function census or independently proved Rust function boundaries. The selected extents cover 3,364 bytes; this number is not a reconstruction denominator.

### Connection to the existing configuration evidence

The retained `constants` packet identifies the `/cham` and `/static_config` template entries and the `NvTestnet` fallback; `RE-015-format-prefix-correction-94` establishes the relevant compiler-stamped interpretation of the `c0` template token. This packet follows a separate consumer. Its selector reads RIP-relative slot `0x576e928`; the actual RELATIVE records bind that slot to cell `0x577b288`, and the cell to the previously studied initializer `0x164ff00`. In the two sentinel arms, the selector passes cell `+0x18` through the string adapter at `0x15861b0`. Earlier evidence associates that field with the selected configuration directory. The runtime bytes of that field are unknown.

The 64-bit word tested below belongs to the downstream selector input. It is distinct from the configuration cell's byte at `+0x48` used in the existing AWS-name investigation; no value of one is inferred from the other. The old 76-name table is not reproduced.

### Selector and complete format entries

The first word at the input pointer is loaded at `0x15861d7`. `neg` at `0x15861dd` followed by `jo` at `0x15861e0` selects `0x1586227` for the signed-minimum bit pattern. The subsequent immediate compare and `jne` select the second and ordinary cases. Both global cases test the cell's `+0x50` word and call the slow initialization boundary when it is nonzero. A normal return resumes at the same prefix-setup point.

| First word | Selected entry VA | Complete bytes | Argument adapter |
| --- | --- | --- | --- |
| `0x8000000000000000` | `0x1f3db9` | `c0 18` + 24-byte `/hyperliquid_data/db_hub` + `00` | global field `+0x18`, `0x15861b0` |
| `0x8000000000000001` | `0x1ea808` | `c0 1b` + 27-byte `/hyperliquid_data/no_db_hub` + `00` | global field `+0x18`, `0x15861b0` |
| any other bit pattern | `0x1ea44d` | `c0 00` | input string adapter `0x1589f60` |

The ordinary adapter follows the input pointer and loads its words at `+0x08` and `+0x10`; the global adapter loads the corresponding words directly from the global field. Under the previously established format-token interpretation, the two first entries append the displayed suffix to the selected global field, while `c0 00` displays the supplied argument without a literal suffix. This does not establish that arbitrary 64-bit words form valid objects, the runtime directory, or any filesystem operation.

### Entry, sorting and state publication

| Selected extent | Observed role in this route |
| --- | --- |
| `0x4adda00..0x4addb60` | Formats the input, prepares the two-key range, calls the builder, publishes the input and returned map words, and releases the temporary buffer. |
| `0x15861d0..0x1586308` | Selects the three entries and supplies the appropriate argument, with two once-initialization slow paths. |
| `0x15861b0..0x15861c4`; `0x1589f60..0x1589f77` | The global-field and input-field adapters tail-call the same external formatting slot. |
| `0x489d9c0..0x489db89` | Takes a record vector from the existing collector boundary, sorts the applicable small range, allocates a root and calls the insertion body. |
| `0x428f680..0x428fd68` | Consumes sorted 16-byte records, handles equal adjacent keys, and publishes keys and pointers into a leaf. |
| `0x44c8670..0x44c8730`; `0x4900d10..0x4900e00` | Release the remaining iterator or record vector, including conditional reference decrements and storage release. |

In the entry, the stores at `0x4adda70`, `0x4adda79` and `0x4adda82` set range start `0`, range end `2` and the two bytes `00 01`. The call at `0x4adda9b` reaches the new builder. Its call at `0x489d9d3` reaches the previously documented directory-guard collector. That collector and its guard are external boundaries in this packet; its loop and guard behavior have prior evidence in `RE-009-owned-db-dir-guard-94`.

For a normal collector return containing the two distinct input keys in corresponding 16-byte records, the observed route is:

1. A nonempty vector reaches `0x489dac6`. Counts 2 through 20 take the local unsigned-key insertion-sort route; a count of 21 or more takes a separate external sort boundary. The modeled two-record sequence `0, 1` is already ordered.
2. `0x489da0e` requests a 112-byte root allocation. The root's first word and its 16-bit field at `+0x62` are initialized to zero; the builder also initializes tree height and total count to zero. The iterator uses 16-byte records.
3. In `0x428f680`, distinct keys reach the insert sequence at `0x428f7f8`. For the two-record case, the leaf count changes from zero to two, key bytes occupy root `+0x64` and `+0x65`, the paired pointer words occupy `+0x08` and `+0x10`, and the total count becomes two. The split branch requires an existing leaf count of at least 11, so this two-record route does not take it.
4. Once the iterator is exhausted, `0x44c8670` releases its backing allocation when its capacity is nonzero. The builder returns three map words; the entry writes the original three input words to output offsets `+0x00..+0x17` and the map words to `+0x18..+0x2f`, then conditionally releases its formatted temporary.

The models in `evidence.json` also exercise reversed keys and equal keys as controls on the observed compare-and-shift sequence. Equal adjacent keys release the earlier record reference and retain the later record before insertion. These are static models, not executions of the capture; larger input behavior and source-level container identities are outside the claim.

### Failure and cleanup boundaries

| Condition or protected call | Observed route |
| --- | --- |
| The formatter returns nonzero | `0x4adda57` reaches the 55-byte diagnostic referenced at `0x706a56`, the error call at `0x4addb00`, and `ud2` if it returns. |
| The selector/formatter call unwinds | The entry's exception table associates its protected range with landing pad `0x4addb1b`, which conditionally releases the first temporary. |
| The map-builder call unwinds | Its protected range selects landing pad `0x4addb08`, which conditionally releases the moved temporary before shared input cleanup. |
| Shared input cleanup | The signed comparison with `0x8000000000000002` excludes both sentinel words; zero is also excluded. Other qualifying words take the external release call, conditional on the object satisfying the input representation. |
| Root allocation returns zero | `0x489da1c` reaches the allocation-error call at `0x489db41`; its exception-table entry names the vector cleanup at `0x489db6e`. |
| A record reference reaches zero during a selected cleanup | The cleanup bodies call the external destructor boundary; nonzero reference counts continue the loop. |

These records establish local branches and encoded landing pads, not that every external call returns or unwinds in a particular way. The prior guard's own rejection behavior is not reanalyzed here.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. There is no component build, lockfile, target execution, raw or normalized byte comparison, or helper/data/relocation closure claim. The inferred reference files use path and map abstractions but do not supply authority for the selected sentinel layout; their labels cannot replace the selected bytes. The packet's small abstract models describe only the stated branch cases and do not establish runtime equivalence.

The focused unittest has ten tests with no skips. It checks the authenticated capture, complete selected entries and relocation chain, selector boundaries, ordered/reversed/equal two-record models, two exception landing pads and independently calculated relative operands. Negative controls alter a same-sized input, a selected instruction, an otherwise unpinned FDE byte, a template terminator and an exception header; they also reject wrong transfer targets, wrong relocation addends, ambiguous sections, out-of-range addresses and a NOBITS address. The producer verifies all eight full FDE byte hashes in addition to the whole-input hash.

## Results and limitations

The focused ten-test suite, artifact verification, catalogue check and inventory/literal reproduction passed. The read-only preflight reported `analysis_ready: true`, `exact_rebuild_ready: false` and `captured_binaries_executed: false`. The producer and focused tests were also run with a Python-only `PATH`; two independently generated directories with different hash seeds and time zones matched byte for byte. Imported-file and reference-pin verification passed using a separate writable LFS storage setting; an initial run with the environment's default read-only LFS storage failed before that setting was supplied.

The selected normal path reaches publication only conditional on the external formatter, previously studied collector and allocation/cleanup boundaries. The collector's whole behavior, exceptional action semantics, larger map splits, actual filesystem effects, concrete global directory and caller reachability are unresolved. No whole-node or component coverage, Rust equivalence, or progress gate is claimed; global configuration remains 0/4. Next question: which still-unowned caller constructs each sentinel value, and under what conditions is the resulting input passed to this entry?
