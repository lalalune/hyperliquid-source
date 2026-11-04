# RE-015: configuration field to a name-gated presence flag in node 115

On node #115, `chain_to_replica_s3_bucket` is the first optional map in the selected configuration object, and a name-gated lookup turns the presence of its `Testnet` or `Mainnet` entry into a caller's stored flag; an empty string is present, so treating the flag as a nonempty-string test would reconstruct the wrong state.

- Component ID: `constants`, task RE-015, with the RE-001 FDE and relocation dependency.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is an unlicensed lead only; no reference implementation is copied.
- Claim status: observed target bytes, selected FDEs, relocation records, direct transfers, field and name comparisons, result stores, and selected normal and exception edges; inferred source-level roles and a possible later consumer; unresolved helper internals, runtime object identity and end-to-end behavior.
- Scope included and excluded: the selected JSON field arm and optional map, key and value routing, a local replacement and insertion boundary, the configuration-object initializer, publication callbacks, name-gated accessor and a caller's flag write. The associated flag consumer is analyzed conditionally by its compatible offset; its actual instance linkage is unproved. The existing static-configuration and filesystem-predicate functions are ownership boundaries, as are other JSON fields, the binary-format path and complete helper implementations. No component gate is requested.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3 or compatible Python 3. The producer reads the complete #115 image, checks its SHA-256 before interpreting it, imports the repository's shared ELF and FDE readers, excludes non-file-backed sections when translating VAs, and invokes no external programs. It never executes either captured binary or reads a live configuration file. The evidence contains no credential values. The length/transfer decoder adapts independently authored MIT-licensed repository history, blob `b23d5808399c7b055601ca7525ddda9ae8bbf7f0`, with a closed set of additional byte encodings; it is not an emulator. GNU objdump 2.42 was used only for human inspection. Its text is not an input to any generated table or test.

```sh
python3 tools/re015_config_gate115.py --out research/work-items/RE-015-replica-bucket-presence-115
python3 -m unittest tests.test_re015_config_gate115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-replica-bucket-presence-115 && sha256sum -c MANIFEST.sha256)
```

To check deterministic generation with two different hash seeds and timezones, replace each placeholder with a distinct writable directory relative to the repository root:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/re015_config_gate115.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/re015_config_gate115.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

If the retired capture is separately available, the following optional command authenticates it before independently reading the historical entries, name descriptors, lookup comparisons, and both field-classifier paths. It prints the historical comparison and does not change the generated #115 evidence:

```sh
python3 tools/re015_config_gate115.py --out <tmp-dir-three> --compare-94 references/can1357-hl/bin/hl-node-mainnet-new
```

The old image is not required by the default generator or focused tests. Its full SHA-256 is `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. All findings below retain their own release and linked-ELF virtual-address coordinate system. File offsets are independently section-mapped in the tables; addresses are not process-rebased addresses. The input digest and all output hashes are reproducible; the manifest covers this README and every generated file except itself.

## Evidence

`functions.tsv` records the 19 selected unwind-described half-open extents, their FDE/CIE/LSDA coordinates, section-mapped offsets and full-range hashes. These extents are not a complete function inventory. `instructions.tsv` partitions those ranges with the admitted encoding set and checks direct intra-range branch targets as instruction starts; this does not establish reachability of every byte or decode an entire program. `branches.tsv`, `transfers.tsv` and `contracts.tsv` separate all selected decoded transfers from 206 review anchors. `exception-sites.tsv` records 204 encoded call-site ranges and landing pads, without interpreting action/type tables. `normal-flow-witnesses.tsv` gives 15 conservative witnesses; conditional edges are over-approximated, calls are assumed to return normally, and unmodeled indirect jumps stop traversal.

| Selected FDE start | Bounded role and connection |
| --- | --- |
| `0x1568b20` | Reads the static-configuration cell, formats the selected filename and calls the document loader; selects copied or default output and a distinct unwrap boundary. |
| `0x15016f0` | Uses two file-predicate outcomes and a transformed path, then selects a read and parser boundary. The predicate's implementation is an existing PR boundary. |
| `0x15750f0`, `0x1593db0` | JSON document and root-object adapters; enter the field visitor and retain separate trailing-input, object, depth and closing-error paths. |
| `0x157ef70`, `0x155e2f0` | Field visitor and selected borrowed-name classifier; the 26-byte field selects one jump-table arm. |
| `0x15d1eb0`, `0x1593780` | Optional-map adapter and JSON map reader; parse the selected value and stage map updates. |
| `0x14bcbe0`, `0x15915f0`, `0x14be0b0` | Key envelope, quoted-key adapter and exact four-name classifier. |
| `0x1596700`, `0x156e440` | String-value boundary and new-key insertion path, including allocation and a separate nonempty-node helper boundary. |
| `0x1543f50`, `0x154d160` | Two relocation-bound callbacks that invoke the initializer and copy its result into the selected cell. |
| `0x154aa00`, `0x51cf360` | Name-gated map lookup and a caller that stores a one-byte presence flag. |
| `0x51fc3e0`, `0x4e39e40` | Separate flag-reading consumer, tag and conversion branches, and the selected downstream state update. |

### Configuration entry and failure paths

The selected initializer loads slot `0x64e0918`, whose RELATIVE relocation names cell `0x64f06c0`, and uses its string-like field at `+0x18`. It supplies full entry `0x43058f` (`c0 11 /api_secrets.json 00`) to a formatter boundary at instruction `0x1568b56`. The linked source-location descriptor says `base/src/api_secrets.rs`; neither the live path nor file contents are observed. The prior #115 static-configuration packet owns the initialization of the first cell. This packet independently records the full `/cham` entry at `0x44ab69` and `/static_config` entry at `0x4401ef` as release-bound context, without selecting the already owned functions that reference those entries.

The loader at `0x15016f0` tests the original formatted path, transforms it, and tests the transformed path. A false first predicate selects loader tag 2; the initializer then writes a default object whose first word is zero. A false second predicate selects the distinct tag-3 error route. The selected text-read or JSON-parser error also reaches tag 3, and `0x1568b92` sends that tag to the unwrap-diagnostic call and `ud2` boundary. This is a static failure path, not a claim about a particular filesystem or process. The transformed name controls a separate format decision; its full contract is not established, so the JSON branch below is conditional on the selected route rather than assumed for every path.

On the JSON route, `0x15750f0` delegates to root adapter `0x1593db0`, which tests the opening byte and calls visitor `0x157ef70`. The document adapter accepts only bytes 9, 10, 13 and 32 in its selected trailing-whitespace loop; another trailing byte produces local error code `0x16` after the visitor result. Root/depth/close error construction and cleanup remain distinct; the producer records their instructions and exception records, not an exhaustive JSON grammar.

### Field-to-map binding

The borrowed key classifier at `0x155e2f0` admits a 26-byte bucket through relative table slot `0x4674a8` to `0x155e58b`. Two overlapping 16-byte comparisons read `0x4529c0` and `0x4536a0`; together they cover every byte of `chain_to_replica_s3_bucket` and produce tag `0x22` at `0x155e605`. The other tested 26-byte spelling has its own earlier success; a nonmatch in this bucket returns the local unknown tag. The visitor's relative table slot for `0x22` resolves to `0x157f3c4`. The second key representation in the visitor is a separate boundary and is not assumed equivalent merely from this one branch.

The selected field slot starts with unseen marker 2. A second occurrence branches from `0x157f3cd` to a full `duplicate field` template and the 26-byte spelling, then reaches the visitor's tag-2 error write at `0x158157d` on the recorded normal-return witness. On a first occurrence, the selected colon route calls optional adapter `0x15d1eb0`. Its `null` path returns option word 0; its non-null path calls map reader `0x1593780` and returns option word 1 on the selected success route or tag 2 on error. At visitor completion, the unseen marker selects a zero default, while a seen option selects the saved 32-byte field. The field's first 32 bytes are the first bytes of the visitor output, carried through the document, root-adapter and loader copies into the initializer's output and then into cell `0x64f0210`. The individual instructions, selected normal witnesses and relocation bindings make this a #115-specific connection; they do not establish that every external helper returns or that every malformed document takes the same error path.

The selected map key adapter can reach `0x14be0b0`, which checks complete lengths and bytes for `Local`, `Sandbox`, `Testnet` and `Mainnet` and returns keys 0, 1, 2 and 3 respectively. On the selected map route, bad opening input, exhausted input, missing colon, nesting limits and key/value errors lead to separate error construction or cleanup boundaries. At equal keys, `0x1593a00` saves the old value and replaces its three words. The old first word is doubled modulo 2^64 at `0x1593a17`; only a nonzero doubled result reaches the selected free call. Thus both zero and `0x8000000000000000` skip that call at this raw machine-code boundary. The latter is an out-of-domain synthetic control, not a claim that a valid value has that representation. New keys reach `0x156e440`; its empty-root path requests `0x120` bytes, initializes a node count at `+0x112`, writes a key at `+0x114`, writes the three-word value and increments the collection count. The nonempty-node split/rebalance helper and allocator failure behavior remain boundaries.

### Publication, lookup and flag

Slot `0x64e0b40` relocates to cell `0x64f0210`; its initial relocation names `0x1568b20`. The two selected callback slots bind `0x154d160` and `0x1543f50`. Each selected callback obtains the initializer result and requests a `0x1c0`-byte copy to the cell, conditional on its pointer/state checks and normal returns. The once implementation and concurrent publication order remain unproved.

The accessor `0x154aa00` reads the name byte at the first cell's `+0x48`. At the selected comparison sites, byte 5 selects chain key 2 and byte 18 selects chain key 3; all other byte values reach the local missing-result route. The selected #115 descriptors independently contain `NodeTestnet` at index 5, `Ed` at 17, `Ee` at 18 and `NvTestnet` at 33. Assigning these descriptor indices to the actual runtime name byte also relies on the prior #115 name-classifier evidence; descriptor order alone does not prove that linkage. Under that linkage, `NodeTestnet` selects `Testnet`, `Ee` selects `Mainnet`, and the earlier observed `NvTestnet` default selects neither.

For a selected name the accessor checks the second cell's guard, requires first word 1 and a non-null root, then traverses key bytes using count `+0x112`, key base `+0x114`, value stride `0x18` and child pointers at `+0x120`. An absent option, null root, missing key or unsupported name writes first word `0x8000000000000000`. A hit with zero length returns first word 0 and pointer 1; a nonempty hit requests allocation and copies the value. Allocation failure takes a distinct nonreturning boundary. These observations assume well-formed structures and successful external operations; corrupt tree behavior and the full allocator contract are not inferred.

A RELATIVE slot ties the call at `0x51d0992` to the accessor. The caller reads the first output word, compares it with `0x8000000000000000`, writes the inequality result at destination `+0xb68`, and conditionally frees a present nonempty copy. In the selected constructor FDE, a conservative normal-flow traversal of 964 `(instruction, rbp-state)` pairs establishes the sentinel register at both the lookup call and comparison. It admits both edges of every conditional, stops at returns and traps, and assumes calls preserve the SysV callee-saved register and return normally. It does not model exceptions, runtime inputs or other callers.

| Selected condition | Accessor result / caller flag |
| --- | --- |
| Name byte 33, or any unsupported byte | Missing sentinel / 0. |
| Name 5 or 18; map absent, root null or selected key missing | Missing sentinel / 0. |
| Selected key exists with a zero-length value | First word 0, pointer 1 / 1; no result-buffer free. |
| Selected key exists with a nonempty value and allocation returns | Length and copied pointer / 1; the caller reaches its result-buffer free. |
| Nonempty value and allocator reports failure | Allocation-failure boundary; no flag result is claimed. |

A separate callback at `0x51fc3e0`, bound by a selected relocation, also tests a byte at object `+0xb68`. If its initial 64-bit tag equals 2, zero flag forwards the original 12-byte value; nonzero flag reaches a binary64 `0.1` scale boundary and two checked range branches. A rejected range or zero helper result selects the 12-byte fallback at `0x4679d0`; the selected routes meet at `0x4e39e40` and then drop the input. A first-word tag other than 2 whose low 32 bits equal 3 takes the drop-only route; other tags take a separate handoff. These are static byte-level branches and synthetic boundary cases, including out-of-domain tags. Matching `+0xb68` and a callback relocation do not prove that this callback receives the particular constructor's object; actual object identity and clock values remain open.

The selected handoff receives the callback object at `+8`, a 12-byte value and the input object. After its input helper returns, `0x4e39e88` tests whether the existing word at handoff-object `+0x48` equals the signed-minimum sentinel. A sentinel skips the update and frees a returned buffer only if its first word is neither zero nor the sentinel. Otherwise, a returned sentinel reuses the current value; a non-sentinel enters a construction and old-value-drop boundary, then writes five 16-byte blocks to `[+0x48,+0x98)`, a 32-bit word at `+0x98` and bytes at `+0xa8` and `+0xa9`. Both active routes call `0x50e39e0`; if it returns, they store the forwarded 12 bytes at `+0x9c` and `+0xa4`. The optional later calls depend on additional state. The FDE's exception table covers the old-value-drop call and points to `0x4e39fe9`, which writes the prepared five blocks before the unwind-resume boundary. The complete construction, old-value-drop, update and unwind-action semantics remain unresolved; the 36 handoff cases model supplied raw words and normal returns only.

### Historical cross-check

The separately authenticated #94 image has full `/cham` entry `0x1fc0ec` and instruction `0x164f840`, and `/static_config` entry `0x1ef5f5` and instruction `0x164fbae`. The optional comparison independently verifies their bytes and RIP targets. Its `NvTestnet` descriptor is index 32 at `0x5668488`, while #115's selected descriptor is index 33. The #94 accessor `0x1404ef0` compares 5 and 17; the #115 accessor compares 5 and 18. For the same 26-byte field, the #94 borrowed JSON classifier's success at `0x13c73a0` and its separate binary classifier's success at `0x13c8497` both store `0x29`; #115's selected borrowed JSON classifier stores `0x22`. The historical comparison checks both sets of #94 bytes and the #115 collector extracts its own data; it does not reproduce the 76-name table or relabel historical addresses as #115.

`templates.tsv`, `format-references.tsv`, `data-anchors.tsv`, `descriptors.tsv`, `relocations.tsv` and `dispatch.tsv` contain the corresponding file-backed bytes and addends. The 418 field probes, 212 chain-key probes, 256 name-byte rows, 16 tree cases, 24 update cases, 7 replacement-word cases, 24 loader cases, 13 lookup cases and 60 consumer cases, and 36 downstream handoff cases are explicit synthetic models. They are deductions tied to selected instructions, not target executions, real configurations or proof that every modeled input is reachable.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependency closure, compiler/linker flags, two-build output, raw and normalized code comparisons, relocation/vtable closure and whole-ELF equivalence are **not yet implemented/measured**. No normalization masks are used. The file, formatting, allocation, synchronization, generic string, tree split/rebalance, source-value production and the next downstream update helper remain boundaries. No runtime or differential test is claimed.

The 32 focused unittest methods passed without skips. Controls include wrong image digest, modified body, ambiguous and NOBITS mapping, duplicate or truncated relocations, out-of-range symbol, corrupted pool entry, changed instruction and branch, jump target inside an operand, changed SIMD constant, wrong classifier byte, unsupported decoder encoding, malformed LSDA, missing CFG witness, changed sentinel and register-writer operand directions, all 256 name bytes, all one-bit variants of the selected field and chain names, valid and invalid synthetic trees, and modular release boundaries. The replacement-word test also covers all 65,536 low-word values against an independent bit-mask oracle.

## Results and limitations

The selected denominator is 19 FDEs / 39,587 bytes, 8,007 admitted instruction rows, 1,052 direct branches, 566 selected call or indirect-transfer rows, 51 selected dispatch slots, 20 selected relocation slots, 9 descriptors, 3 complete template entries and 204 encoded exception call sites. These counts cover this packet only; they are not component coverage, remaining engineering effort or equivalence. The captured binary was not executed and no network, private keys, live state, or credential file was accessed.

Artifact/signature verification, catalogue consistency and inventory reproduction passed. Two differently seeded and time-zoned generations matched byte for byte with no binutils on `PATH`; only this packet's focused tests were run under the specified memory constraint. The available main checkout and the supplied PR file snapshot were reviewed; some open PR bodies were unavailable, so a final independent address-level ownership check remains necessary before submission. No hosted CI or container result is claimed. The `constants` gates remain false. Next question: bind the constructor's concrete object to the flag-reading callback and close the nonempty-node insertion, error cleanup and subsequent update contracts against #115.
