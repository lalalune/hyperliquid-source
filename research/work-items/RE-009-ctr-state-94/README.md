# RE-009: selected `ctr` state codec in node #94

Node #94's `ctr` path contains seven default-elided words and an `AbstractionCounters` value whose three five-word groups and two time-pair children now have recoverable field orders and defaults, enabling a reconstruction to preserve their nested omission and duplicate-field decisions.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; unlicensed `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` was used for leads only, with no reference code copied.
- Claim status: observations are the authenticated bytes, selected FDE intervals, calls, data references, comparisons and branch destinations. Codec, reader/writer association and type interpretations are inferences identified below. Runtime reachability and the semantic expansion of abbreviated names remain unresolved.
- Scope included and excluded: the `ctr` JSON-shaped field wrapper, selected JSON-shaped and MessagePack-shaped value writers, their default predicate and nested writers, and matching candidate readers including duplicate-name decisions, plus the shared five-word and time-pair child paths. Excluded are the already studied containing state writers and readers, the full `ac` child grammar and MessagePack-shaped child readers, generic integer/date/string helpers, file and hash ownership, other releases and any target execution.

## Reproduce

From the repository root, with Python 3.12.3 and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/ctr_state94.py --out work/ctr-state-a
python3 tools/ctr_state94.py --out work/ctr-state-b
diff -r work/ctr-state-a work/ctr-state-b
python3 -m unittest tests.test_ctr_state94
python3 tools/catalogue.py --check
(cd research/work-items/RE-009-ctr-state-94 && sha256sum -c MANIFEST.sha256)
```

Compare the six generated files with the packet:

```sh
for f in evidence.json fields.tsv nested-fields.tsv five-word-fields.tsv scenarios.tsv time-pair-scenarios.tsv; do
  cmp "work/ctr-state-a/$f" "research/work-items/RE-009-ctr-state-94/$f"
done
```

The generator checks the complete input SHA-256 before parsing and uses the repository's `tools/elf_index.py` and `tools/fde_extents.py` for sections and FDEs. It snapshots mutable inputs, refuses ambiguous or non-file-backed VA mappings including `SHT_NOBITS`, verifies fixed instruction shapes, resolves signed displacements and three selected `R_X86_64_RELATIVE` relocation slots, and writes deterministic files. It neither invokes external programs nor executes the capture. GNU objdump 2.42 was used only for bounded human interpretation; its output is not a generator input or a generated evidence file. Evidence has no operand masks. It contains linked virtual addresses, corresponding file offsets, exclusive FDE ends, raw selected bytes and per-body SHA-256 hashes.

## Evidence

### Field wrapper and value writers

The field wrapper `0x27b11b0..0x27b1279` points to the three literal bytes `ctr` at `0x3ef18f` and calls the selected value writer `0x275dff0` at `0x27b120a`. The writer's selected nested field is passed the same value base; this packet does not reanalyse its enclosing writer. The MessagePack-shaped counterpart is `0x275e5c0..0x275e995`. Their eight selected key references appear in the same order. The offset is relative to the value base, not a file offset:

| Key | Value offset | Selected writer condition |
| --- | --- | --- |
| `tn` | `+0xc8` | 64-bit word nonzero |
| `vn` | `+0xd0` | 64-bit word nonzero |
| `tc` | `+0xd8` | 64-bit word nonzero |
| `sc` | `+0xe0` | 64-bit word nonzero |
| `to` | `+0xe8` | 64-bit word nonzero |
| `so` | `+0xf0` | 64-bit word nonzero |
| `ac` | base | default predicate returns zero |
| `ad` | `+0xf8` | 64-bit word nonzero |

The decoder verifies each writer key's RIP-relative displacement and bytes, the seven scalar loads or address calculations, the eight MessagePack-shaped presence gates, the corresponding JSON-shaped gates, the scalar writer calls, and each selected name/value failure branch. `fields.tsv` gives the key sites and reader arms; `evidence.json` retains the test bytes and actual call/branch targets. The MessagePack-shaped writer counts the selected fields before invoking the header helper. Its serializer byte at `+0xb` selects one header helper when zero and the other when nonzero. For 0, the selected names are omitted; for 1, all selected names are passed to the key writer. Conditional on successful preceding helper calls, a reported name or value failure takes a recorded exit before the next field.

There is a noteworthy distinction for the **noncanonical value 2**, which is not asserted to be a valid serializer mode: the name tests for `tn`, `vn`, `tc`, `sc`, and `ac` compare the byte with 1, while those for `to`, `so`, and `ad` test it for zero. Thus, if those paths are entered with byte 2, only the latter three pass their name tests. `name_at_flags_0_1_2` in `fields.tsv` records these three boolean outcomes per field; it is not a claim that such a mode occurs at runtime. Normal reconstruction should retain the canonical 0/1 cases until callers establish the domain.

### Nested `ac`

The default predicate `0x282fcc0..0x282fe06` makes two calls through slot `0x576e890`, each with immediate `719163` (`0xaf93b`). The ELF relocation at the slot has addend `0x151f6f0`. Each zero return takes a separate failure branch before the comparisons. Let the two nonzero 32-bit results be `D1` and `D2`. The predicate returns 1 exactly when its observed comparisons all succeed:

- Every 64-bit word at offsets `+0x30, +0x38, ... , +0xc0` is zero: 19 comparisons and 19 branches to the common false return.
- The 64-bit words at `+0x00` and `+0x18` are zero; the 32-bit words at `+0x08` and `+0x20` equal `D1` and `D2`, respectively; the 32-bit words at `+0x0c`, `+0x10`, `+0x24` and `+0x28` are zero.

A human-readable excerpt of the selected comparison tail is:

```text
282fdc0  cmp qword ptr [rbx], 0
282fdc6  cmp dword ptr [rbx+0x08], ebp
282fdd9  cmp qword ptr [rbx+0x18], 0
282fde0  cmp dword ptr [rbx+0x20], ecx
```

The already published [day-count constructor evidence](../RE-001-daycount-date-94/README.md) independently evaluates this helper for the same input as the Unix epoch date. Combining that result with the observed calls supports an epoch-date interpretation for both words; the helper body is not re-analysed here. In particular, replacing `D1` or `D2` by a literal zero is not supported by these observations. Byte ranges outside the listed comparisons, including `+0x2c`, are not constrained by this predicate.

The nested JSON-shaped writer `0x28e6540..0x28e6f91` and MessagePack-shaped writer `0x28e6fa0..0x28e7562` use these nine keys in order. `nested-fields.tsv` records the two writer sites, the candidate-reader arms and their duplicate diagnostics.

| Key | Selected source word offsets | Observed presence decision |
| --- | --- | --- |
| `p`, `m`, `l`, `L` | `+0x30`, `+0x38`, `+0x40`, `+0x48` | respective 64-bit word nonzero |
| `M` | `+0x50` through `+0x70`, stride 8 | at least one of five words nonzero |
| `b` | `+0x78` through `+0x98`, stride 8 | at least one of five words nonzero |
| `c` | `+0xa0` through `+0xc0`, stride 8 | at least one of five words nonzero |
| `s`, `t` | tuple bases `+0x00`, `+0x18` | selected composite default tests use the helper results and additional words |

The group and tuple guards, child calls and their failure branches are retained as raw windows. The nested JSON-shaped reader initializes absent scalar and group values to zero and uses the same helper slot for absent `s` and `t`, with failure on zero helper result. The abbreviations' business meanings remain unresolved.

### Five-word children of `M`, `b`, and `c`

The three group arms call the same JSON-shaped writer `0x2978870..0x297900e` and the same compact writer `0x297a740..0x297a9ae`, passing their respective group bases. Both writers use five one-byte keys, and each compact value call has a separately checked failure exit. Offsets in this table are relative to the particular group base:

| Key | Group offset | Omit when |
| --- | --- | --- |
| `t` | `+0x00` | 64-bit word is zero |
| `s` | `+0x08` | 64-bit word is zero |
| `c` | `+0x10` | 64-bit word is zero |
| `u` | `+0x18` | 64-bit word is zero |
| `l` | `+0x20` | 64-bit word is zero |

The compact writer counts nonzero words before the header, conditionally supplies each name, and checks the name and value results. Its entire selected gate and call span is pinned without masks; `five-word-fields.tsv` lists each omission target and failure exit. The JSON-shaped child writer checks each of the same words and keys. The nested JSON reader calls `0x1cdf140..0x1cdfc25` from all three group paths and branches on the child result. That reader's checked 19-entry dispatch covers byte values `c` through `u`: five entries have the keys above and duplicate-specific diagnostics; the other 14 reach the selected unknown arm. This does not determine the full sequence grammar, all malformed-input behavior, or business meanings.

### Shared `s` and `t` time-pair children

The compact nested `s` arm calls `0x2201310..0x2201493`; `t` calls `0x297a230..0x297a28b`, whose checked tail jump reaches that same writer. Within either child, a nonzero 64-bit word at `+0` selects key `n`. Three 32-bit words at `+8`, `+0xc` and `+0x10` select key `t` unless they equal `(0xf6401a, 0, 0)`. The fixed packed value is read directly from the immediate at `0x2201335`; the selected call for `t` passes the bytes `Time` to a generic helper. Name and value failures take recorded exits. A changed word, including either trailing 32-bit word, makes `t` present in the static model.

The nested JSON reader calls `0x1cae020..0x1cae719` for both children and checks each returned status. That reader distinguishes one-byte `n` and `t`, has separate duplicate diagnostics, delegates each value, and checks the child status. On the observed end-of-map route, absent `n` supplies zero; absent `t` calls the same relocated helper with `719163` and follows a failure branch if it returns zero. The previously published day-count evidence identifies that helper's corresponding packed result as `0xf6401a`, independently matching the compact writer immediate. This comparison supports the default relationship; the generic `Time` encoding itself is not recovered.

### Candidate readers and failures

The JSON-shaped reader's type-error path passes the vtable at `0x568da60` to an error helper. Its formatter slot relocates to `0x276bb50`, which passes the exact bytes `struct ExchangeCounters` to an indirect formatting call. The nested JSON-shaped reader's corresponding vtable at `0x568e660` relocates its formatter slot to `0x28e82a0`, which supplies `struct AbstractionCounters`. The generator checks both vtable headers, relocation slots, formatter instruction shapes, lengths and literal bytes. These are observed expected-value messages, not proof of original source declarations.

The MessagePack-shaped candidate `0x19bb570..0x19bd7ea` and JSON-shaped candidate `0x1caa410..0x1cab737` call classifiers `0x26bff40` and `0x26bffd0`, respectively. The two compare the same eight two-byte keys and classify all other lengths or values as the separate unknown index. Both candidate map readers dispatch the recognized indexes to eight independently recorded presence tests and field-specific duplicate diagnostic literals. Their unknown arms reach other helpers; those helpers' complete behavior is not established. The end-of-map windows supply zero for absent scalar slots; absent `ac` follows a separate initialization route. Child parsing failures can occur earlier than these end-of-map decisions.

The nested candidate readers `0x181c4a0..0x181eaeb` and `0x1d06dc0..0x1d08016` both check a one-byte key and use selected relative dispatch tables covering 41 byte values from `L` through `t`. In each table, nine entries identify `p`, `m`, `l`, `L`, `M`, `b`, `c`, `s`, and `t`; the remaining 32 table entries reach the respective unknown arm. Each known arm first tests its own presence state and branches to a diagnostic carrying that key on a repeat. Out-of-range and other-length keys take the separately selected unknown route. These statements concern the recorded map paths and do not establish full input grammar or error precedence.

### Inferences

The references to `ctr`, the matching ordered keys, selected call edges, duplicated fields, output offsets and shared nested default predicate support treating these functions as a field writer and corresponding candidate readers. JSON and MessagePack are interpretations of the selected marker, key and helper patterns, consistent with the repository's earlier bounded codec evidence. The epoch-date interpretation combines the helper binding here with the earlier day-count packet; the matching `0xf6401a` immediate is independently observed in the compact child writer. The expected-value messages support the labels `ExchangeCounters` and `AbstractionCounters` for these candidate readers, but the original Rust declarations, signedness and expanded meanings of abbreviations are not established by this packet. A reader/writer relationship is not proof that any particular on-disk file uses either route.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo build, compiled-code comparison, relocation normalization, target execution or actual snapshot fixture is claimed. Generic helper bodies, indirect-call closure and full raw/normalized whole-function comparisons remain open. The FDE endpoints describe unwind ranges; they do not by themselves establish all function boundaries, cold fragments or source ownership.

`scenarios.tsv` contains five explicitly synthetic outer presence models, and `time-pair-scenarios.tsv` contains six synthetic child cases. The tests cover all 256 outer and 32 five-word presence masks and all 65,536 possible two-byte key values in static models tied to the checked compare/branch shapes. They are not executions of the node. Other controls change the digest, key-compare opcode, duplicate branch, table entry, omission gate and zero-comparison branch, and exercise missing file-backed mappings, including NOBITS. The modified-code and modified-table tests rebind the outer digest before analysis so that structural guards, rather than the digest guard alone, reject the corruption.

## Results and limitations

The focused suite contains 16 passing tests and no skips. The packet records 20 selected FDE intervals, eight outer fields, nine nested fields, five five-word child fields and two time-pair child fields; it checks 16 outer, 18 nested, five five-word and two time-pair duplicate branches, two 41-entry nested dispatch tables, one 19-entry child dispatch table and 19 nested zero-word tests. Those denominators describe selected paths, not function coverage, source equivalence or a complete storage implementation. No milestone gate is requested.

The business identities and complete encoding of the `ac` subfields, the generic `Time` value, arbitrary malformed inputs, sequence-reader length behavior, noncanonical serializer modes, helper bodies, persistence wiring, state-root ownership and cross-version compatibility remain unresolved. Next, recover the generic `Time` representation and the compact child readers, then compare complete fixtures in a separately authorized offline harness.
