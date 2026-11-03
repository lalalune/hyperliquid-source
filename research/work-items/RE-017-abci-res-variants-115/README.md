# RE-017: result variants in the loader-linked block fingerprint

The selected post-block `res` encoder distinguishes an error case from fifteen result variants and fixes the nested order, cancel and delayed layouts needed to reconstruct part of the fingerprint input.

- Component ID: `abci`; this also informs the RE-009 state-result serialization question.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; navigation-only, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference source was copied.
- Claim status: instructions, byte strings, selected FDE records, transfer targets and encoded offsets are observations. Wire examples, source-level names, pointer identity across earlier packets and the formatter binding are conditional inferences. Runtime behavior and a full source schema remain unresolved.
- Scope included and excluded: the previously unowned result encoder, fifteen table arms, their thirteen distinct payload entrypoints, delayed-ID and order/cancel-status encoders, selected failure paths and a bounded synthetic wire model. The earlier loader, its GOT and existing call sites, block engines, row serializer, shared string/header/integer writers and formatter remain attributed boundaries. This does not cover every payload body, all begin/action/end-block branches, all state-root inputs, live execution or a component gate.

## Reproduce

From the repository root, with the authenticated node artifact and the existing shared ELF and FDE parsers present:

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_abci_res_variants115
python3 tools/abci_res_variants115.py --out research/work-items/RE-017-abci-res-variants-115
mkdir -p work/re017-res-python
ln -sf "$(command -v python3)" work/re017-res-python/python3
PYTHONHASHSEED=1 TZ=Etc/UTC PATH=work/re017-res-python python3 tools/abci_res_variants115.py --out work/re017-res-one
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu PATH=work/re017-res-python python3 tools/abci_res_variants115.py --out work/re017-res-two
diff -r work/re017-res-one work/re017-res-two
diff -r -x README.md -x MANIFEST.sha256 work/re017-res-one research/work-items/RE-017-abci-res-variants-115
(cd research/work-items/RE-017-abci-res-variants-115 && sha256sum -c MANIFEST.sha256)
```

The comparison directories must initially be empty. Python 3.12.3 on Linux x86-64 generated the records; the extractor uses the standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. It verifies the complete #115 digest before parsing or creating the output, rejects ambiguous or non-file-backed mappings, checks the selected FDEs against the shared unwind index and parses the specified x86 encodings directly. It starts no external program. GNU objdump 2.42 was used only for human inspection during research; generated files and tests do not parse or invoke it. Neither captured executable was run.

The following optional check was also run with a separately available historical input. It checks the #94 digest and original Location and comparison before writing the same #115 evidence; it does not require the historical input for normal regeneration.

```sh
python3 tools/abci_res_variants115.py --historical-node references/can1357-hl/bin/hl-node-mainnet-new --out work/re017-res-history
diff -r work/re017-res-one work/re017-res-history
```

## Evidence

### Relationship to existing work

The #115 `l1/src/abci/state.rs:123:37` Location and comparison are rechecked as contextual identity anchors in `summary.json`; the associated loader and its call sites remain owned by earlier work. Open PR #2047 proposes the loader-to-owner route. PR #2243 proposes the subsequent expanded-state item route, including selected saturating writes and a conditional root-child connection. PR #2332 follows a later block-result vector into the fingerprint serializer and records the existing call to this packet's entry `0x59229a0`. These prior records are dependencies, not new claims in this packet. In particular, matching the two prior row strides does not establish that a particular state-mutating item supplies a particular serialized `res` value. The worker, loader and scheduler have not been observed executing, and the earlier proposals must be reviewed independently.

All addresses below are linked ELF virtual addresses before load bias. `functions.tsv` retains file offsets, FDE/CIE coordinates, hashes and raw bytes for 22 selected, nonoverlapping unwind extents totaling 9,237 bytes. FDEs describe unwind ranges, not a complete function census or a source-level boundary proof. `variants.tsv` gives each signed table displacement, selected arm, header calls, literal and payload call; `branches.tsv` gives 184 selected conditional instruction bytes and their decoded targets. `order-statuses.tsv`, `status-paths.json`, `literals.tsv`, `format-widths.tsv`, `delayed-projection.json`, `failure.json` and `summary.json` retain the remaining direct byte-derived facts. The selection is bounded; it is not a percentage of the component.

### Entry and choice of status

At `0x59229c0`, `80 3e 0f` compares the first input byte with 15. The equal arm calls the shared string writer with `err`; it loads two words from input `+0x10` and `+0x18` before passing them as the response string pointer and length. The other arm calls that writer with `ok` and invokes `0x4d8fcd0` with the original input address. On writer mode 1 the outer arm additionally writes the literal keys `status` and `response`; on mode 0 those keys are skipped. The two arms request an outer container with two elements from the established header helpers.

At `0x4d8fce4`, the input byte selects a signed four-byte table displacement. The table starts at `0x914e5c` and its entries for indexes 0 through 14 point to the arm starts below. The preceding result encoder handles byte 15 separately. This is a map of selected indexes, not a claim that all are runtime reachable or that values outside this set have a defined meaning.

| Byte | Literal written | Table arm | New payload entrypoint | Payload supplied |
| ---: | --- | --- | --- | --- |
| 0 | `order` | `0x4d8fcf7` | `0x4e0d3c0` | address of input `+8` |
| 1 | `cancel` | `0x4d8febb` | `0x4e0d4c0` | address of input `+8` |
| 2 | `createVault` | `0x4d8fe1d` | `0x4e0dc50` | address of input `+1` |
| 3 | `liquidation` | `0x4d8fe55` | `0x4e0c0b0` | address of input `+8` |
| 4 | `twapOrder` | `0x4d8fd93` | `0x4e0c240` | address of input `+8` |
| 5 | `twapCancel` | `0x4d8fee9` | `0x4e0fb90` | address of input `+8` |
| 6 | `trailingStop` | `0x4d8ff45` | `0x4e0c7c0` | address of input `+8` |
| 7 | `createSubAccount` | `0x4d8fe83` | `0x4e0ef70` | address of input `+1` |
| 8 | `token` | `0x4d8ffa1` | `0x4e0dd90` | word at input `+8` |
| 9 | `spot` | `0x4d8fdef` | `0x4e0dd90` | word at input `+8` |
| 10 | `validatorVote` | `0x4d8ff73` | `0x4e0f0d0` | byte at input `+1` |
| 11 | `governanceProposal` | `0x4d8fd65` | `0x4e0fc50` | address of input `+1` |
| 12 | `setGlobal` | `0x4d8fdc1` | `0x4e0fbf0` | address of input `+8` |
| 13 | `delayed` | `0x4d8ff17` | `0x4e0c110` | address of input `+8` |
| 14 | `default` | `0x4d8fd25` | none selected | no payload call |

The named form checks mode exactly equal to 1 before writing `type`; the ordinary payload wrappers check mode for nonzero before writing `data`. The result and variant container choices test zero versus nonzero. The two canonical modes are therefore separately described below; mode values other than 0 and 1 are not modeled as if all tests were interchangeable.

### Order and cancel status arrays

The new `order` and `cancel` payload wrappers tail-call `0x518a280` and `0x518a630`. On the selected successful path, each makes a one-element container, writes the key `statuses` only when mode equals 1, and calls its respective array FDE. Both read a pointer at payload `+8` and a count at `+0x10`; the selected order loop advances by 48 bytes per element, while the cancel loop advances by 24. These observations do not assert an allocator layout or collection validity for arbitrary input.

The order array's selected direct element encoder uses a second signed-displacement table at `0x91d214`. Five selected entries lead to these literals; the `filled` and `resting` nested values still contain additional helpers that are not closed here.

| Element byte | Entry | Literal or selected form |
| ---: | --- | --- |
| 0 | `0x5188f4a` | `filled`, followed by a nested value |
| 1 | `0x518909e` | `resting`, followed by a nested value |
| 2 | `0x518903a` | `waitingForFill` |
| 3 | `0x518906a` | `waitingForTrigger` |
| 4 | `0x5188fcb` | `error`, followed by the element's string pointer and length at `+0x10` and `+0x18` |

On the selected direct cancel path, an element whose first word is `0x8000000000000000` writes `success`. A different first word calls new helper `0x5301c00`, which writes a one-entry map marker, the `error` key and the string at that element's `+8`/`+0x10`. Its own capacity, string-key and value failures have separate branches. The array FDEs have distinct header, element, allocation and counter-limit paths; their counter-limit diagnostics reach `ud2` if the called boundary returns. These are observations of selected static paths, not a claim that a particular status is reachable or that prior output is rolled back on failure.

### Selected nested data and failure paths

For `token` and `spot`, the same new payload FDE forwards the supplied word to the existing unsigned writer after the optional `data` key. For `validatorVote`, the new payload FDE combines the supplied byte with `0xc2` and sends the resulting marker to the existing marker helper; for input bytes 0 and 1 this gives `c2` and `c3`. No other byte is claimed to be a valid boolean representation.

The `createVault` and `createSubAccount` payloads request a 42-byte destination for 20 input bytes, and `governanceProposal` requests 66 bytes for 32 input bytes. The three new call sites address the formatter slot already documented in PR #2332. On the prior packet's formatter binding, normal return and intact input, these widths correspond to a `0x` prefix and two lowercase hexadecimal characters per input byte. The slot's runtime binding and the formatter's whole contract are not newly established here.

The `delayed` payload adds 8 to the original variant address. Its load at `0x4e0c1aa` reads a word a further `0x10` bytes on and passes it to the existing unsigned writer under the `delayedUntil` key. It then forwards the first two words of that payload to new FDE `0x4e0d7a0`, which writes `id`, then `height` and `tx_index` in order, using the existing unsigned writer for each word. Relative to the original variant address, the three words are at `+0x18`, `+0x08` and `+0x10`. These are layout and label observations, not a proof of their domain meaning. The projections assume the ordinary calling convention, stable input and no conflicting alias writes.

| Selected condition | Byte-backed continuation |
| --- | --- |
| Outer, variant or delayed container helper returns a leading word other than 2 | The corresponding error arm stores the high-bit sentinel and forwards the helper's selected result words. |
| A selected string writer returns a value other than 2 | A separate return block records the sentinel and the writer's returned words; later selected fields are bypassed. |
| A selected nested payload returns a first word other than `0x8000000000000004` | The caller copies its three-word result into its own output instead of continuing the selected success arm. |
| Validator marker buffer reaches the selected capacity equality | The FDE enters a growth path. If the checked growth-status byte is nonzero, it writes output words `0x8000000000000000`, 0 and `0x2600000003` at offsets 0, 8 and 16. The detail word's source-level meaning is unknown. |
| Any earlier write or helper changes an input, writer or buffer through an alias | The conditional projections and wire examples do not establish the resulting behavior. No rollback is assumed. |

The prior fingerprint packet reports that a non-success serializer result reaches its diagnostic path. That is prior contextual evidence; this packet does not claim that a particular serialized value reaches that path at runtime or that the fingerprint is a state root.

### Release separation

The retired #94 clue remains tied to SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its Location `0x56dfbf8`, referenced at `0x3273856`, names `state.rs:107:37`, and its comparison at `0x3273871` uses 2. The separately authenticated #115 Location `0x64767a8`, referenced at `0x3c1352f`, names `state.rs:123:37`, with comparison 1 at `0x3c1353b`. The optional historical check reads both artifacts independently using the shared section parser. A common path suffix is a navigation clue; it does not equate the functions, result tags, layouts or behavior across releases.

### Inferences and synthetic examples

Under the existing header and string-writer contracts, successful mode 0 uses array containers and successful mode 1 uses named map containers. For example, the bounded model encodes mode 0, `default` as `92 a2 6f 6b 91 a7 64 65 66 61 75 6c 74`; mode 0, `delayed` with three synthetic small words 7, 8 and 9 yields `92 a2 6f 6b 92 a7 64 65 6c 61 79 65 64 92 07 92 08 09`. These are derived model fixtures, not bytes captured from a running node. The model intentionally rejects noncanonical modes and unsupported cases or widths; that is a model boundary, not a statement about native input validation.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler/linker options, two-build comparison, raw and normalized implementation comparison, masks, complete helper/data/relocation closure and whole-ELF equivalence: **not yet measured**. The Python model is limited to selected successful branches and is not an implementation of the complete result format. No target machine code is used as an implementation.

## Results and limitations

The focused suite passed 33 tests with zero skips. Negative controls mutate every selected table entry and label, invert every selected variant branch, damage the special discriminator, selected branch destinations, status stride, payload projection, formatter width, FDE body, Location and artifact digest, and reject ambiguous, NOBITS and out-of-range mappings. The tests also exercise selected order and cancel statuses, string-length, small unsigned, canonical boolean, fixed-width and delayed-layout model boundaries. Two regeneration runs with different hash seeds and time zones matched byte-for-byte with a Python-only `PATH`; the optional #94 check produced the same #115 files. Artifact signature/hash verification and catalogue consistency passed. No repository-wide unittest run, captured-node execution, hosted CI or container result is claimed.

The rest of the thirteen payload bodies, their larger serializers, result construction, the precise producer-to-fingerprint vector join, runtime aliasing, all block variants, full state roots and snapshot compatibility remain open. No component progress gate is requested. Next question: prove whether the 64-byte projected item results become the nested 64-byte fingerprint rows on the same selected worker path, and close the required intervening copies without re-owning earlier FDEs.
