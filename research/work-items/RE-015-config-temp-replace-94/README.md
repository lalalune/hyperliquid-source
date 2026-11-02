# RE-015: configuration-rooted temporary path and replacement routing

Node #94 builds a temporary replacement path from the lazy configuration's directory field, tries a second prefix after a directory-creation failure, and returns the first path if both attempts fail and both error callbacks return normally; a reconstruction must preserve those choices and the separate link and final-transfer error boundaries.

- Component ID: `constants`, task `RE-015`; the selected consumer also crosses into file utilities.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a lead.
- Claim status: observations are selected instruction bytes, FDE extents, relocation bindings, argument slots and local branches. Names such as directory predicate and replacement entry are inferences. External helper internals and runtime effects are unresolved.
- Scope included and excluded: thirteen selected FDE extents from entry to local return or external boundary, two complete format templates for the path builder, the entry's token template, its directory-error template, local tag gates and slice-view helpers, metadata and link adapters, long-link callbacks and normal-return failure routing. Existing initializer, name parser, incoming component-reader state, destination-parent helper, final-transfer helper, formatting, allocator, dynamic error callbacks and exceptional edges remain boundaries. Node #115 and visor are different targets. No full-component gate is requested.

## Reproduce

From the repository root, using Python 3.12.3 and the authenticated artifacts:

```sh
python3 tools/config_temp_replace94.py --out research/work-items/RE-015-config-temp-replace-94
python3 -m unittest tests.test_config_temp_replace94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
```

To check deterministic output, replace each placeholder with a distinct writable relative directory and compare:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_temp_replace94.py --out <first-output>
PYTHONHASHSEED=119 TZ=Pacific/Honolulu python3 tools/config_temp_replace94.py --out <second-output>
diff -r <first-output> <second-output>
```

The producer hashes the entire target before parsing, uses the shared `elf_index` and `fde_extents` readers, excludes non-file-backed sections from VA translation, and reads instruction, template and relocation bytes directly. Its narrowly scoped x86-64 length and transfer decoder rejects unsupported or truncated encodings and branches into instruction operands. It neither executes the capture nor invokes external programs. GNU objdump 2.42 was used for human inspection only; none of its output is consumed by the producer or tests. Hashes for all retained files are in `MANIFEST.sha256`.

`functions.tsv` supplies FDE metadata and whole-range hashes; `instructions.tsv` and `transfers.tsv` retain all admitted instruction encodings and transfers in those ranges. `relocations.tsv` includes the selected GOT and dynamic-symbol bindings. `templates.tsv`, `witnesses.tsv`, `branches.tsv`, `cfg.tsv`, `component-tags.tsv`, `tail-components.tsv`, `adapter-lengths.tsv`, `callback-edges.tsv`, `cases.tsv`, `long-link-cases.tsv` and `summary.json` are generated from the capture and stated models. The case tables are conditional static models, not recorded node executions. The format templates are stored as hex so their exact length and terminator remain visible without treating a runtime path as known.

## Evidence

All addresses are linked ELF virtual addresses; file offsets are separately retained in the generated tables. A decoded FDE is an unwind-described extent, not a complete function census or proof of source ownership.

| Inferred role | FDE extent, end exclusive | Bytes |
| --- | --- | ---: |
| owned, NUL-checked buffer | `0x13464d0..0x134664a` | 378 |
| directory predicate | `0x144a070..0x144a1e4` | 372 |
| metadata-existence predicate | `0x144a2f0..0x144a3dc` | 236 |
| directory-error adapter | `0x144a4e0..0x144a5fc` | 284 |
| configured temporary-path builder | `0x144d0d0..0x144d468` | 920 |
| replacement entry | `0x37eaa70..0x37eac47` | 471 |
| metadata adapter | `0x4edfb40..0x4edfd58` | 536 |
| link adapter | `0x4ee0000..0x4ee02fa` | 762 |
| long-source link callback | `0x4ee0300..0x4ee04a1` | 417 |
| long-destination link callback | `0x4ee04b0..0x4ee04f0` | 64 |
| long-input adapter | `0x4ee60a0..0x4ee613f` | 159 |
| backward component classifier | `0x4ee9b80..0x4ee9cae` | 302 |
| component slice view | `0x4ee9cb0..0x4ee9f47` | 663 |

### Configuration binding and complete pool entries

The existing constants and build-mode packets relate the configuration cell to the original static-config initializer and its directory field. Here the new builder at `0x144d0d0` loads slot `0x576e928`; its `R_X86_64_RELATIVE` addend is `0x577b288`. The cell's initializer relocation points to `0x164ff00`, an existing-work boundary. A nonzero state word at cell offset `0x50` takes the Once boundary; after normal return, the builder passes cell offset `0x18` as its first format argument. The actual directory is unknown.

At `0x144d0f4`, the builder selects the three-byte slice `74 6d 70`; it supplies the caller's pointer/length pair as a third argument. The complete template referenced at `0x144d162` begins at `0x1f04e5` and is `c0 01 2f c0 01 2f c0 00`. The first, second and third argument slots and the two separator bytes are visible in `witnesses.tsv` and `templates.tsv`. The old template correction interprets `c0` as an argument placeholder; under that contract, the constructed text combines the configuration directory, the three-byte component and the supplied input, in that order.

The replacement entry's template at `0x1e8ad5` is length-delimited: a 28-byte literal ending in a separator, an argument placeholder and a terminator. Its literal spells the replacement utility's name; the following argument comes from an external token-producing boundary. The builder's second template at `0x1e7299` contains the five literal bytes `2f 74 6d 70 2f`, a placeholder and a terminator. Its sole argument is the previously built path. These observations do not require any particular runtime home or directory, and do not prove filesystem normalization.

Human-readable excerpts, with bytes also retained in generated records:

```text
0x144d10f  4c8b3512183204   load the configuration pointer through slot 0x576e928
0x144d116  418b4650         load the cell's state word at offset 0x50
0x144d122  4983c618         advance to the field at offset 0x18
0x144d162  488d357c33dafe   select the complete three-argument template at 0x1f04e5
0x37eab8d  ff152db3f801     call through slot 0x5775ec0 to the link adapter
0x4ee0297  ff154b708900     call through slot 0x57772e8, imported symbol linkat
```

### Component tag and directory decisions

The builder's primary and fallback copies perform an 8-bit addition of `0xf9`, compare against `3`, and branch on the unsigned result. For each copy, exactly byte values 7, 8 and 9 enter the optional slice-reader route; all other bytes bypass that route. `component-tags.tsv` enumerates the full byte domain from the instruction immediates. When a slice is absent or the conversion result takes its failure branch, the original input slice is retained. The incoming component-reader state and conversion helper remain external boundaries, so identifying the selected slice as a parent directory is an inference rather than a complete path-parser proof.

These are local component-result bytes, not the AwsName discriminants from the existing 76-name inventory. In particular, evaluating byte 32 in this gate takes its bypass branch; no dataflow from the earlier NvTestnet default into this component-result byte is established.

The local normal-return routes are:

| Candidate and create outcomes | Observed local route |
| --- | --- |
| Primary directory predicate nonzero | Return the first formatted path. |
| Primary predicate zero; first create result zero | Return the first formatted path. |
| Primary predicate zero; first create result nonzero | Build a second formatted path and repeat the candidate check. |
| Fallback predicate nonzero, or fallback create result zero | Return the second path. |
| Both create results nonzero | Adapt the second error, call its dynamic target, release the second string when indicated, call the first error's dynamic target, and return the first path if those calls return. |

Both create calls receive an object initialized with dword `0x1ff` and byte `1`; their internal filesystem behavior is an external boundary. The predicate first calls `0x144a2f0`, whose metadata result tag 2 yields zero. If that predicate returns nonzero, `0x144a070` calls the metadata adapter a second time, and for a non-2 result tests `(mode & 0xf000) == 0x4000`. The repeat is visible and must not be folded into a single guaranteed observation. The component-result and tag-2 tests, subsequent branches, and mode mask are all pinned in generated records.

### Selected slice-view helpers

The slice-view helper at `0x4ee9cb0` receives a component-state object and returns a pointer/length pair at `0x4ee9e5f`. Depending on its incoming state bytes, it removes leading empty or single-dot components and calls the backward classifier at `0x4ee9b80` while examining the remaining suffix. Its three call sites compare the returned tag with 10; a different tag joins the return path, while tag 10 can take a checked length-subtraction and repeat. Underflow branches to a separate failure boundary. Root and state flags affect which loop runs, so this does not establish the state supplied by the earlier component-reader call.

For a final separator-delimited component after the helper's prefix adjustment, the classifier's byte tests select the following tags:

| Component bytes | Tag |
| --- | ---: |
| Empty or `2e` | 10 |
| `2e 2e` | 8 |
| Any other component | 9 |

The classifier searches backward for byte `0x2f` and returns a consumed count, tag, pointer and length. `tail-components.tsv` supplies nine conditional examples; the focused tests cover the one- and two-byte non-separator domains and corrupt a branch polarity. The tag-10 trim and the special treatment of the two-dot component are observations; interpreting the returned pair as the high-level parent path still depends on the pre-existing component-reader boundary.

### Replacement entry and error routes

`0x37eaa70` calls the metadata adapter for the first input. A tag-2 result goes to an error-conversion and dynamic-call boundary, then continues to token construction if that call returns. Only when the first tag is not 2 is the second input's metadata requested; its tag-2 path rejoins the same boundary. When both tags are not 2, the entry compares metadata words at result offsets `0x20` and `0x28`. If both words agree, it returns zero without building a path or calling the link adapter. If either differs, it obtains a token, formats the utility-specific input, and invokes the configured path builder.

After path selection, the link adapter is called. A nonzero result goes through an error-conversion boundary and then to local string cleanup; the destination-parent and final-transfer calls are bypassed. A zero link result calls the already documented destination-parent boundary; a nonzero result bypasses the final-transfer boundary. Only the zero-result route calls the final-transfer boundary. The selected entry then returns the resulting word after local cleanup. External calls and their possible unwinds are not modeled as guaranteed normal returns.

The link adapter's direct short-buffer path tests each supplied length against `0x17f`. Length 383 follows that path; length 384 selects a separate long-input helper. On the direct path, an embedded zero takes the adapter's error route. The relocation at `0x57772e8` binds the call to dynamic symbol `linkat`; the call site loads `-100` for both directory descriptors and zero for flags. A return of `-1` reads `__errno_location`, shifts that value by 32 and sets low bits to 2; otherwise the direct call returns zero. `adapter-lengths.tsv` and the mutation tests cover the boundary.

### Long-link callbacks and buffer rejection

When the source is long, `0x4ee0000` passes the address of callback `0x4ee0300` to `0x4ee60a0`; when only the destination is long, it passes callback `0x4ee04b0`. The first callback repeats the destination length check and, if that destination is also long, passes the second callback to the same adapter. These address loads, direct adapter calls and the register-indirect dispatch are pinned in `callback-edges.tsv` and `witnesses.tsv`. Under normal allocation and conversion returns, with no embedded zero in short inputs, the resulting call sites are:

| Source length | Destination length | Local linkat site |
| --- | --- | --- |
| at most 383 | at most 383 | `0x4ee0297` |
| above 383 | at most 383 | `0x4ee0453` |
| at most 383 | above 383 | `0x4ee04cb` |
| above 383 | above 383 | `0x4ee04cb` |

`0x4ee60a0` calls the owned-buffer converter at `0x13464d0`. The converter allocates and copies a length-plus-one buffer, searches for zero bytes and records the discovered position on its non-sentinel route. Its no-zero route calls a separate buffer finalizer and, if that returns, stores the `0x8000000000000000` sentinel. The long-input adapter invokes its supplied callback only on the sentinel route; a non-sentinel result bypasses the callback. After a callback returns, it writes zero to the buffer's first byte and conditionally releases that allocation. Allocation failure, the finalizer's internals and exceptional behavior remain boundaries.

The converter has scalar and word-at-a-time zero-search loops. The test suite reads the two word-search constants directly from the capture and compares their arithmetic with an independent byte-by-byte oracle over all 65,536 two-byte prefixes with fixed nonzero suffixes and 2,040 separate zero-position patterns. This is a static arithmetic control, not target execution or an exhaustive proof over all 64-bit words. `long-link-cases.tsv` covers the 15 selected length/converter-status combinations; it assumes the short inputs contain no embedded zero and does not model allocation failure.

The metadata adapter similarly distinguishes short and long input. Its short path invokes an earlier adapter; only the tag-3 route calls the `stat64` import. That success route copies 144 bytes into the result at offset `0x20` and stores tag zero. A direct `stat64` failure forms the same low-bit error encoding and stores tag 2. Other metadata-adapter returns and long-input behavior remain external boundaries. The first two copied words are consistent with file identity fields on this target, but their source-level type is an inference.

### Comparison with the reference lead

The reference's hard-link helper supplies a relative utility-specific path and describes a temporary-name generator. The captured call chain instead passes the utility-specific input to a builder that prefixes the lazy configuration directory and has a second prefix. This is a byte-grounded difference in path construction, conditional on the prior format-template and field interpretations. The token source, directory-slice helpers and final transfer remain external, so the lead's token algorithm, cleanup behavior and full file semantics are not accepted or rejected here. No reference code is copied.

## Implementation and comparison

Independent Rust reconstruction: **not yet implemented**. Cargo manifest, lockfile, compiler/linker flags, two-build result, target behavior comparison and raw or normalized binary comparison: **not yet implemented or measured**. No normalization masks are applied to the retained machine bytes. Helper, call-target, relocation, remaining dynamic dispatch, exceptional control flow, data closure and whole-ELF equivalence remain separate gaps.

The 25 case rows are predictions under the stated normal-return and external-status assumptions. They exercise both metadata failures, matching and mismatching words, primary/fallback selection, link failure, destination-parent failure and final-transfer outcomes; they do not execute the node or establish filesystem results. Corruption controls cover artifact identity, FDE range, instruction truncation and branch alignment, branch polarity and target, relocation addends and symbol names, template termination, field windows, tag boundaries and CFG properties.

## Results and limitations

The collector records 13 selected FDE extents, 5,564 bytes, 1,439 admitted instruction encodings, 173 conditional branches and 344 total transfer rows. It checks 45 named branch contracts, 26 named indirect-call contracts, 8 callback/direct-call contracts and 21 named relocation contracts, resolving 27 selected relocation slots. It emits 37 structural normal-return CFG propositions, 512 component-tag rows, 9 conditional tail-component examples, 24 length-boundary rows, 25 replacement scenarios and 15 long-link scenarios. These counts are scoped to the listed extents or explicit model domains, not the node or component as a whole.

The focused suite passed 43 tests with no skips. Artifact SHA-256 and signatures, catalogue consistency and inventory/literal reproduction passed. Both independent regeneration runs matched byte for byte and matched all retained generated files. The full repository unittest suite was not run under the stated memory constraint; no hosted CI result is claimed.

The separate `python3 tools/verify_imports.py` check failed during the fresh-index status check for the pinned reference. Repeating that step exposed a Git LFS clean filter attempting to write inside read-only Git metadata. The ordinary reference HEAD and status checks succeeded. This failure is not an artifact/signature or full import-verification pass.

No node or visor execution, network access, key use, chain action, Rust build or binary-equivalence claim was made. FDE extents do not prove all function boundaries; the decoder is limited to the selected bytes and does not model exception-table edges, arbitrary indirect calls or the full x86 ISA. The operating-system calls, allocator/finalizer behavior, live directory contents and long metadata-input path are untested. The pre-existing initializer and final transfer are intentionally not reclaimed. All four `constants` milestones remain unaccepted.

Next question: after coordinating ownership of the existing component-reader, destination-parent and final-transfer helpers, resolve the incoming component-state contract and long metadata-input path, then establish the actual failure cleanup and runtime root under an explicitly authorized isolated harness.
