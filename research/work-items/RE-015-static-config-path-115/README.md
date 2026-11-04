# RE-015: node 115 static configuration from lazy initialization to name selection

Node 115 stores `NvTestnet` as discriminant 33, selects it after a normally returned static-file read or parse error, and instead consults a separate `aws_name` file when an otherwise well-formed object reaches its closing delimiter without that field; these distinctions let a reconstruction avoid importing node 94's incompatible discriminants or assuming the illustrative reference's fallback behavior.

- Component ID: `constants`; task `RE-015`, with RE-001 function-boundary and relocation evidence.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical, unlicensed inferred-reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a lead, not source copied into this packet.
- Claim status: observed byte patterns, FDE extents, relocation bindings, selected control-flow edges, two string-array contents and formatter arms; inferred path and source-level roles; unresolved full helper and parser behavior.
- Scope included and excluded: the initialization and selected normal, missing-name, and failure paths through publication, home selection, directory selection, two file reads and the `NvTestnet` boundary. Included function extents are not claims of exhaustive CFG recovery. Other names' parser paths, all filesystem states, concurrency semantics, and full component ownership are excluded.

## Reproduce

Run from the repository root on Linux x86-64, with Python 3.12.3 or a compatible Python 3 and the pinned #115 artifact available. The producer imports the repository's `tools/elf_index.py` and `tools/fde_extents.py`, authenticates the complete input before parsing, and reads bytes only. It does not invoke binutils or any external process. GNU objdump 2.42 was used separately for human inspection; no objdump output is parsed or included in generated evidence. No captured executable is run, and no live paths or environment values are accessed through it.

```sh
python3 tools/re015_static_config_115.py --out research/work-items/RE-015-static-config-path-115
python3 -m unittest tests.test_re015_static_config_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
```

To compare two independently generated evidence sets, replace the placeholders with two distinct writable repository-root-relative directories:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/re015_static_config_115.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/re015_static_config_115.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The producer writes only the 18 generated evidence files described below. `README.md` and `MANIFEST.sha256` are not producer outputs; the manifest covers this README and those files. All addresses are linked ELF virtual addresses (VAs) unless labelled file offsets. Section mapping gives `.rodata` VA equal to its file offset and `.text` file offset equal to VA minus `0x1000` for these selected coordinates. FDE ranges are half-open unwind-described ranges, independently decoded with the shared parser; they are not a whole-program function census. Byte extraction covers the listed windows and lookup entries; semantic interpretation is limited to the explicitly selected instructions and does not cover every instruction or callee in the listed FDEs.

The historical comparison is optional and does not affect the generated files. If the retired capture is separately available at the indicated repository-relative reference location, this command authenticates its full digest and independently decodes its table and two selected template references before printing the comparison:

```sh
python3 tools/re015_static_config_115.py --out <tmp-dir-one> --compare-94 references/can1357-hl/bin/hl-node-mainnet-new
```

The old binary is not needed for the default producer or focused tests. Historical observations below retain node #94's identity, rather than relabelling its coordinates as node #115.

## Evidence

| Generated file | Bounded content |
| --- | --- |
| `summary.json` | Digest, byte-derived counts and non-claims. |
| `functions.tsv` | 23 selected FDE ranges, FDE/CIE/LSDA coordinates, offsets and whole-range hashes. |
| `calls.tsv` | 52 selected direct or RELATIVE-relocated transfers, with their bytes and resolved targets. |
| `imports.tsv` | 10 selected indirect calls, their dynamic relocation and symbol-name bindings. |
| `branches.tsv` | 52 selected conditional branch encodings, fallthroughs and taken targets. |
| `windows.tsv` | 41 raw byte windows, including surrounding tests, stores and failure paths. |
| `literals.tsv` | Five complete selected suffix entries and the RIP-relative instruction starts referring to them. |
| `diagnostics.tsv` | Five selected diagnostic/key byte strings and their references. |
| `globals.tsv`, `publication-stores.tsv` | Four RELATIVE pointer bindings, selected vtable/header and initial guard bytes, and ten 16-byte publication stores across two callbacks. |
| `names-115.tsv` | 79 target-only discriminator rows cross-checked against both RELATIVE pointer/length arrays and the independent formatter jump arms. |
| `length-dispatch.tsv` | The 12 selected length slots for each of two classifiers. |
| `name-rules.tsv`, `name-probes.tsv` | Three lifted equality branches and 37 finite positive, single-byte-bit-flip and length probes. |
| `directory-cases.tsv`, `reader-cases.tsv` | Nine directory and 12 reader scenarios for small models of the selected branches, with external outcomes supplied as inputs. |
| `value-dispatch.tsv` | All 79 selected quoted-value jump slots and their byte-writing leaves, independently read from the #115 ELF. |
| `table-refs.tsv` | Five selected RIP-relative references that connect the classifiers, formatter and unknown-name error path to these tables. |

### Entry, publication and resulting object

The existing `RE-001-node115-cache-suffix` packet records the consumer's relocation `0x64e0918 -> 0x64f06c0` and a possible initialization path. The new records bind the file's initial RELATIVE relocation at `0x64f06c0` to initializer `0x17785f0`, and bind the two callback slots `0x64b6710` and `0x64b6718` to `0x5944f60` and `0x5940470`. Those slots follow a header containing zero, size 8 and alignment 8. The previous packet supplies the consumer-to-vtable context; this packet independently reads the newly selected callback bodies and relocation bytes.

Each callback reads and clears a pointer in its closure, checks for a null pointer and a state byte equal to 1, calls through the first word of the pointed object, and copies five 16-byte blocks from the return buffer into that object. The selected initial object word relocates to `0x17785f0`. The destination intervals are `[0,16)`, `[16,32)`, `[32,48)`, `[48,64)` and `[64,80)`; the copied padding bytes are not characterized. The initial file bytes at `0x64f0710` are integer 3. Guard transitions, concurrent callers, unwinding behavior of the synchronization helper and a complete vtable ABI remain boundaries, so the static records do not claim a runtime publication order.

Initializer `0x17785f0` calls the home-string routine `0x17782e0`, the selector `0x17780c0`, a metadata-like helper, the shared formatter, and static reader `0x17783e0`. It writes three 24-byte groups at output offsets `0x00`, `0x18`, and `0x30`, followed by a byte at `0x48`. The call arguments and suffix entries support the inference that these groups correspond to home, selected directory, and code directory. This is a selected layout and flow observation, not a complete Rust type or allocation ABI.

### Home and directory decisions

`0x17782e0 -> 0x5c9abb0 -> 0x5c81950` constructs the bytes `HOME` in the binary and reaches the relocated `getenv` symbol. The selected code routes a missing or empty environment result to account lookup, including `sysconf`, `getuid`, and `getpwuid_r`; the fallback's complete account and error semantics are not modeled. The wrapper separately handles a high-bit sentinel and a text-validation result before returning its string-like triple. The local environment was not queried as target input.

The selector `0x17780c0` supplies the full entry at `0x44ab69` (`c0 05 /cham 00`) to formatter `0x141e3a0`, then tests the metadata result. If the metadata tag is not 2 and `(mode & 0xf000) == 0x4000`, it returns the first formatted triple. Otherwise it formats the entry at `0x43de29` (`c0 03 /hl 00`), checks that result, and may call `0x5c8f4c0` with mode field `0x1ff` and option byte 1. A nonzero return reaches the create-error routine `0x1778270`. The initializer checks the selected triple again; a tag-2 result or non-directory mode reaches the diagnostic at `0x445b89`. On the passing branch it formats the complete `/code` entry at `0x43de2f` and passes that result to `0x17783e0`. Creation, metadata and formatter internals beyond the selected calls are not closed.

| Selected condition | Site and taken destination | Selected consequence |
| --- | --- | --- |
| First metadata tag is 2, or its mode is not directory | `0x177812d` fallthrough or `0x1778149 -> 0x177815b` | Examine the second suffix. |
| Second metadata is a directory | `0x17781c3 -> 0x17781e8` | Return the second triple without the creation call. |
| Creation helper returns nonzero | `0x17781e6 -> 0x1778221` | Call `0x1778270`, then the diagnostic boundary. |
| Selected directory fails initializer's second check | `0x1778641 -> 0x17786e6` or `0x1778655 -> 0x17786f0` | Error cleanup and diagnostic path. |

### Static-file and missing-name routes

`0x17783e0` references entry `0x4401ef`, not the text address `0x4401f1`, and passes the formatted result to `0x5ca4940`. That helper's selected path reaches `open64`, `fstat64`, `read`, and `close`, resolved from dynamic relocation and dynamic-symbol bytes. The `open64` and `read` loops compare failures with `-1` and retry after error number 4. The `fstat64` failure branch still reaches the read helper if the intervening helper returns normally; no claim is made that metadata is required for every successful read. One open-error path and the selected read/text-validation error path write `0x8000000000000000` in the first result word. The reader's `neg`/overflow check at `0x177844c` and `0x1778452` sends that sentinel to `mov $0x21,%bpl` at `0x177845c`.

On the non-sentinel branch, `0x17783e0 -> 0x1775dd0 -> 0x17771b0` reads the document. The wrapper checks for non-whitespace trailing bytes using mask `0x100002600`, whose set positions in the checked 0..32 range are 9, 10, 13 and 32. A normally returned nonzero document tag selects 33 at `0x177852c`; a zero tag selects the accompanying parsed byte. This does not assert that a panic or unwind is caught and converted to 33.

The accompanying branch models take metadata, file-read and parser outcomes as abstract inputs. They record conditional consequences of these selected instructions; they do not execute the ELF or establish that every synthetic combination can occur. In particular, the synthetic zero parser tag with value 79 is retained to show that the outer selector itself does not reject that byte; it is not evidence that a valid document produces it.

The document reader recognizes an object or array at the selected top-level dispatch. In an object, it compares the key length with 8 and the key bytes with `aws_name`; a repeated field takes the selected duplicate-field error branch. The value path calls `0x1773070 -> 0x1777080 -> 0x1774100` for the quoted-name case. After a recognized quoted value, the 79-entry table at `0x481928` maps each classifier byte to a leaf that writes the same byte and jumps to the common success-tag write at `0x1773f2d`. For 33 the selected leaf is `0x1773284`. The outer reader transfers the successful value into its own result before the initializer stores it. The field's temporary missing marker is 79, outside the 0..78 name range. When the object closes with that marker, `0x1777a3b` calls `0x1773fd0`; an empty selected array reaches the same helper at `0x1777a21`. These are statically established branches, not an exhaustive JSON schema.

`0x1773fd0` calls `0x1772fa0`, which repeats home and directory selection and references full suffix entry `0x44205d` (`c0 09 /aws_name 00`). It then calls the same read helper, the selected trim-like helper `0x1778840`, and the plain-name classifier `0x1775500`. A read error reaches `0x1774061`; the classifier's 79 marker reaches `0x1774092`. Both paths reference a `Result::unwrap()` error diagnostic and call `0x1680c30` followed by `ud2`. Thus a missing-field fallback-file failure is a separate panic/unwind boundary; it is not established as a normal return of the static-reader default. A successful classifier result returns to the document path and can be stored in the final output byte. The complete Unicode trim, text validation, allocation and file-helper behavior is not claimed.

| Selected outcome | Byte-backed consequence |
| --- | --- |
| Static file helper returns the error sentinel | `0x1778452` falls through to the 33 immediate at `0x177845c`. |
| Document returns nonzero status normally | `0x1778529..0x1778531` retains 33. |
| Document returns zero status normally | The same sequence selects the returned byte; initializer stores it at `+0x48`. |
| Duplicate `aws_name` field | `0x17778bd -> 0x1777e6a`, with the duplicate-field diagnostic and an error return. |
| Missing object field or empty selected array | `0x1777a3b` or `0x1777a21` calls `0x1773fd0` to obtain the name separately. |
| Separate name file read fails or its classifier returns 79 | The distinct unwrap-diagnostic paths end at `ud2` after the panic boundary. |

### Discriminant boundaries and release comparison

The #115 marker at `0x464893` says `variant index 0 <= i < 79`. Two independent 16-byte pointer/length arrays begin at `0x63f8788` and `0x6410ce8`. For each of 79 entries the producer resolves a distinct RELATIVE relocation, reads the file-backed slice and requires both names to equal the corresponding decoded arm of the 79-entry formatter jump table at `0x481bd0`. Each arm's selected `lea`, length and indirect tail slot are independently checked. The quoted-name classifier's unknown-name branch references the second array at `0x1774947`, passes an immediate count of 79 to its error helper, and writes result tag 1. This establishes the selected mapping on this digest, not ownership of every potential reference or behavior on invalid renderer input. The formatter has no checked bound in its selected entry window, so the packet makes no claim about passing 79 or larger to it.

For `NvTestnet`, the plain classifier tests length 9, then XORs the first eight bytes and the last byte against the encoded constants. Equality reaches `0x1775d27`, returning 33. The separate quoted-value classifier's corresponding comparison reaches `0x1774a04`, writing success tag 0 and value 33. The 10-byte `NvTestnet2` predicate reaches `0x1775d63`, returning 34. The recorded finite probes check each single-byte low-bit mutation and the two length boundaries; they only model these equality predicates, not the whole classifiers. In particular, `NvTestnet2` fails the nine-byte predicate but is a valid match of the ten-byte predicate.

The historical comparison used node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its selected table starts at `0x5668288`, its bound diagnostic is at `0x21823f`, and its `NvTestnet` entry is `0x5668488`, referring to `0x2180ff`. The #94 default instruction at `0x164fc56` is `40 b5 20`; #115's `0x177845c` is `40 b5 21`. On #115, index 32 instead names `SoloSandbox`. Comparing the independently authenticated tables finds all 76 old names, 63 with shifted indices, plus `EaTx` at 13, `NvMainnet3` at 37 and `DummyNv` at 39. This is a three-entry target expansion, not a resubmission of the old 76-row table.

| Historical lead | Node #94 entry / instruction VA | Node #115 entry / instruction VA |
| --- | --- | --- |
| `/cham` full template | `0x1fc0ec` / `0x164f840` | `0x44ab69` / `0x17780f3` |
| `/static_config` full template | `0x1ef5f5` / `0x164fbae` | `0x4401ef` / `0x177840e` |
| `NvTestnet` | index 32, table slot `0x5668488` | index 33, slots `0x63f8998` and `0x6410ef8`, formatter arm `0x177502f` |

Those #94 coordinates and bytes are also retained in the historical constants and format-prefix work items at the parent of the source commit. Each #115 coordinate above was separately resolved from the authenticated #115 ELF. No target behavior is inferred from a historical address alone.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo graph, compiler flags, build comparison, raw-equal/normalized windows, relocation masks and full helper closure: not yet measured. No binary bytes are transplanted. The focused controls reject wrong digests, missing or altered relocations, NOBITS and crossing spans, malformed template lengths and terminators, changed formatter arms, altered predicates and branch targets, invalid symbol indices, diagnostic-reference changes, and a shifted publication store. The probes are algebraic predicates extracted from the selected instructions, not execution or emulation of the node.

## Results and limitations

The producer recorded 23 FDEs, 52 selected resolved transfers, 10 imported call sites, 52 selected branches, 41 windows, five suffix entries, five diagnostics, 79 target name rows and 79 quoted-value dispatch leaves. All 20 focused unittest cases passed, including the above corruption controls; both independent output generations matched byte-for-byte. Artifact verification, catalogue consistency and inventory reproduction passed. The repository-wide unittest discovery was not run, in accordance with the task's memory constraint. No component gate is requested: these are partial static observations, not whole-component or whole-ELF equivalence.

The path map stops at shared synchronization, formatting, metadata, creation, string validation, portions of JSON handling, and allocation/unwind boundaries. Actual external values, a complete accepted input grammar, every name classifier branch, all variants of filesystem failure, and the source-built node remain unverified. Next question: recover the remaining document-value and synchronization helper contracts, including their error and concurrency states, before implementing this initializer in Rust.
