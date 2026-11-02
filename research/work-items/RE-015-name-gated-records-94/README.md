# RE-015: recover the small-vault record query and its post-query name gate

Node #94 selects these records by either a 20-byte key or an unsigned threshold, and only after collection applies an AWS-name-dependent slow-path check that excludes the previously identified `NvTestnet` default.

- Component ID: `constants`; task `RE-015`, with an adjacent information-query consumer.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `966865f1637a29ce75b019e1bf11d5529cc6f519`; inferred can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was used as a lead, not copied as implementation.
- Claim status: observation for the selected bytes, relocations, branch targets and unwind ranges; inference for descriptive roles and the link to the earlier configuration interpretation; unresolved for actual request reachability, external helper effects, semantic record types and runtime behavior.
- Scope included and excluded: one bounded handoff from an already-indexed caller, six newly selected unwind extents, their local normal and exceptional paths, and eight relevant name descriptors. The earlier 76-entry inventory, the caller body, remaining external helpers, node #115 and the visor are excluded. No component gate is requested.

## Reproduce

From the repository root with the pinned capture available, Linux x86-64 and Python 3.12.3 were used. The collector and its tests use the standard library and the shared `tools/elf_index.py` and `tools/fde_extents.py` readers. They authenticate the complete node #94 input before generating anything, read only file-backed sections, and call no external program. The captured binary is never executed. The bounded x86 decoder accepts only forms needed by these bodies and refuses unrecognized encodings; it is not a general disassembler. GNU objdump 2.42 was used for human inspection, not to generate evidence or drive tests.

```sh
python3 tools/config_record_query94.py --out research/work-items/RE-015-name-gated-records-94
python3 -m unittest tests.test_config_record_query94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-name-gated-records-94 && sha256sum -c MANIFEST.sha256)
```

For two independent regenerations, use two empty writable directories relative to the repository root:

```sh
mkdir -p work/re015-record-a work/re015-record-b
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_record_query94.py --out work/re015-record-a
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/config_record_query94.py --out work/re015-record-b
diff -r work/re015-record-a work/re015-record-b
for f in work/re015-record-a/*; do cmp "$f" "research/work-items/RE-015-name-gated-records-94/${f##*/}"; done
```

`MANIFEST.sha256` records hashes of the README and retained evidence. `evidence.json` identifies the target digest, constants, per-FDE summaries and counts. `functions.tsv`, `instructions.tsv`, `branches.tsv`, `calls.tsv`, `contracts.tsv`, `relocations.tsv`, `descriptors.tsv`, `lsda.tsv`, `failure-routes.tsv`, `cfg.tsv`, `handoff.tsv` and `synthetic-cases.tsv` are generated entirely from the authenticated bytes and explicitly marked synthetic inputs. Their contents do not depend on binutils output, paths, locale, time or hash seed.

## Evidence

All addresses are linked ELF virtual addresses; the generated files additionally report file offsets. The executable and data sections have different VA-to-file offsets, so the two coordinate systems must not be interchanged. The six selected ranges below are independently read FDE extents. Linear decoding covers each extent and checks that internal direct-branch destinations are instruction starts; an FDE is an unwind range, not by itself proof of a complete function census.

| Selected extent | Local role inferred from its instructions | Bytes |
| --- | --- | ---: |
| `0x2586d80..0x2586eb4` | query wrapper and post-result name gate | 308 |
| `0x27d5d60..0x27d6035` | locked collection and result handoff | 725 |
| `0x257ed30..0x257ef7a` | build the returned vector | 586 |
| `0x24c1430..0x24c1639` | select and copy the next record | 521 |
| `0x250c2b0..0x250c34b` | release one selected row | 155 |
| `0x250f0d0..0x250f4b3` | release the accumulated vector and its rows | 995 |

### The bounded label and handoff

An earlier information-request inventory already indexes the enclosing caller. This packet does not claim or decode that caller's full body. The five-instruction handoff excerpt at `0x27e50bd..0x27e50d9` loads pointer `0x3f3ac6` at `0x27e50bd`, loads length 25 at `0x27e50ce`, and directly calls the selected wrapper at `0x27e50d4`. The exact 25-byte slice is `small_vault_summaries_get`. The preceding byte is `0x65` and the following byte is `0x75`; neither is a terminator. The pointer and length therefore define the slice boundary. Its use as a source-level operation name is an inference; the selected locked body does not itself establish an API endpoint or prove that it uses the label.

The prior `constants` and `constants-aws-name-parse-94` packets bind the global configuration cell and identify byte 32 as the default. Here the instruction at `0x2586de3` references slot `0x576e928`, whose `R_X86_64_RELATIVE` addend is cell `0x577b288`; the selected code reads its name byte at `+0x48` and tests a word at `+0x50`. `descriptors.tsv` reads just the seven selected table slots and the default's slot using their relocations and explicit lengths. This is not a new export of the 76-entry table.

### Comparison with the inferred reference

The reference files are unlicensed, inferred material and are used only to identify questions. The following distinctions bind the query to observed constants without adopting the reference's source-level control flow:

| Reference lead | Binary-backed result and remaining boundary |
| --- | --- |
| `global_constants/static_config.rs` names `NvTestnet` as the default. | The earlier `constants-aws-name-parse-94` packet separately traces fallback to byte 32. This packet reads the descriptor for byte 32 and shows that an actual configuration byte of 32 bypasses the second lazy-state word in this consumer. It does not reanalyze the fallback or show that it was used for a particular request. |
| The same file lists `/static_config` and `/cham` as path suffixes. | The earlier `constants` and `RE-015-format-prefix-correction-94` packets locate and interpret their format-pool entries. This query packet neither re-exports those entries nor proves path creation or file-read behavior. |
| `global_constants/aws_name.rs` assigns source-level names and categories. | This packet extracts the eight relevant pointer-length descriptors and tests the actual bit mask in the selected consumer. The consumer's seven admitted names include both testnet and mainnet spellings; the reference's category labels do not establish which path this consumer takes. |

The threshold value and mask below come from selected node instructions and data, whereas a source-level default or category remains a reference claim until independently matched to a binary path. Reference parsing and environment assumptions are outside this packet.

### The name and floating-point decision

After `0x27d5d60` returns, the wrapper adds two returned binary64 values and compares the sum to the captured binary64 `3.0` at `0x20aab8`. `ucomisd` followed by `jbe` at `0x2586de1` bypasses the configuration access for values at or below 3.0 and for unordered values. For an ordered sum greater than 3.0, the following local decision applies after the configuration initialization helper returns normally:

| Name byte | Observed local path |
| --- | --- |
| `13`, `14`, `18`, `19`, `20`, `21`, `31` | Reaches the second lazy-state word at `0x577ab98`. If that word is nonzero, calls the helper through `0x576e8b8`; if zero, returns the vector. |
| `32`, the earlier packet's `NvTestnet` default | Fails the unsigned `<= 31` bound and returns the vector without reading that second word. |
| Any other byte | Fails the bound or the corresponding bit of `0x803c6000`, and returns the vector. |

The seven selected descriptor texts are `HeavyTestnet`, `HeavyMainnet`, `SoloTestnet`, `SoloMainnet`, `LockerTestnet`, `LockerMainnet` and `SoloSandbox`. The selector is therefore not simply a testnet-versus-mainnet split. An earlier replica-route analysis observes the same mask in a different function; this packet maps its distinct query and iterator path. The existing build-mode packet identifies the second cell's initializer; this packet does not reanalyze it.

The normal-flow graph requires the query call before the configuration load, and no path from that load returns to the query call. Each local normal branch converges on the same 24-byte result copy at `0x2586e10`. These are local control-flow observations under normally returning helpers, not proof about arbitrary side effects of those helpers or concurrent state.

### Record selection, cursor and output

The locked body gets a base pointer from owner offset `+0x578` and a count from `+0x580`; it forms an end pointer with a 120-byte stride and calls the collector. The collector passes an iterator containing current and end pointers, a pointer to a key-filter structure and a pointer to a 64-bit threshold. The iterator loads the threshold through that pointer before choosing a filter, so both input pointers must be valid even when the key branch is used.

| Key-filter flag | Local selector in `0x24c1430` | Mismatch |
| --- | --- | --- |
| Low bit clear | Compare the unsigned 64-bit record word at `+0x40` with the threshold; accept equality or greater. | Advance by 120 bytes and continue. |
| Low bit set | Compare the 16 bytes at `+0x5c` and the next four bytes with the requested 20-byte key. | Advance by 120 bytes and continue. |

The key match reaches the selected-record block without executing the threshold comparison; other flag bits do not switch the branch. `cfg.tsv` records the corresponding bounded structural paths. On a match the iterator writes the next-record pointer at `0x24c14d2` before allocation or nested-copy boundaries. When it reaches the end it returns tag 3. The iterator's matching path copies the record's first 64-bit field into its result; the collector tests its low 32 bits for the same tag 3. Thus, conditional on a matching row having that bit pattern and its copy returning normally, the collector stops after the cursor advances. Whether such a row is valid in real state is unresolved; the synthetic case does not assert that it is.

With no returned row, the collector publishes `(capacity, pointer, length) = (0, 8, 0)`. On the first non-sentinel row it requests 480 bytes, sets capacity 4 and length 1, and copies a 120-byte record. Later rows append in order, calling a separate growth helper when length equals capacity. The helper's growth policy is not recovered. An input tag of at least 2 takes an additional branch: if a selected nested field is nonzero but its associated pointer is zero, the code reaches a panic helper and `ud2`. The nested clone and allocator implementations remain boundaries.

### Time-result and optional-call branches

The locked body calls the same external sampling boundary before lock acquisition, after acquisition and after release. It calls a second external boundary to compare the first two samples and, later, the second and third. For each comparison result, a nonzero leading tag bypasses the conversion block and leaves the corresponding binary64 result at zero; tag zero reaches the conversion block. The first result is prepared before collection and the second after release. These control-flow observations do not establish the external helpers' semantics or that either result represents elapsed wall time.

The wrapper also loads a byte from the original owner's `+0x588` and passes it to the locked body. After the collector, lock release and second comparison, a zero byte bypasses an indirect call; any nonzero byte reaches the call through slot `0x576e8f8` with integer argument 50. The RELATIVE relocation for that slot has addend `0x13c9e20`. The normal path resumes at the same result copy after that call returns. Neither the meaning nor the unit of the argument is established by this packet.

| Input to local branch | Observed result |
| --- | --- |
| First comparison tag nonzero | First binary64 output remains zero; continue to collection. |
| Second comparison tag nonzero | Second binary64 output remains zero; continue to the optional-call branch. |
| Extra flag zero | Skip the helper call and copy the result. |
| Extra flag nonzero | Call the helper with argument 50, then copy the result if it returns normally. |

### Lock and failure paths

The locked body first examines the word at owner offset `+0x568`. Bit `0x08`, an unsigned value at least `2^64 - 16`, or a failed compare-exchange selects the external slow helper. Otherwise its locked compare-exchange attempts to add 16. After the collector returns, a locked exchange-add subtracts 16. The pre-subtraction word masked with `0xfffffffffffffff2` is compared with `0x12`; equality reaches a separate wake-helper call. The implementation and effects of both external helpers remain unresolved.

The row cleanup first tests the allocation length at row offset `+0x20` and, when nonzero, passes its pointer at `+0x28` to the deallocation slot. It then compares the low 32 bits of the row tag with 2; tags below 2 skip a nested walk, while other tags reach a separately bounded iteration helper until that helper returns zero. The vector cleanup visits `length` rows at a 120-byte stride and tests the backing allocation's **capacity**, not its length, before passing `capacity * 120` to the deallocation slot. A nonzero capacity still takes that call if an artificial, out-of-range capacity makes the 64-bit product wrap to zero. Whether such a capacity can exist in valid node state is unknown.

`lsda.tsv` contains the selected call-site ranges and landing offsets from five extents; the row cleanup FDE has no LSDA. It does not interpret exception action or type tables. The checked local handoffs in `failure-routes.tsv` include:

| Boundary | Statically observed landing and cleanup |
| --- | --- |
| Collector's first vector-allocation failure helper | `0x257ef3a` passes the already selected row to a cleanup boundary. |
| Later iterator call | `0x257ef61` leads to the accumulated-vector cleanup boundary. |
| Vector growth call | `0x257ef49` leads through pending-row and accumulated-vector cleanup boundaries. |
| Nested-copy or nested-pointer panic call | `0x24c161b` conditionally frees the selected row's separate byte allocation before unwind resumes. |
| Locked collector call | `0x27d5fbc` reaches the atomic release and conditional wake boundary before unwind resumes. |
| Optional flag-controlled helper | `0x27d5fa7` passes the saved result to the external cleanup boundary at `0x277cb60` before unwind resumes. |
| Either wrapper initialization call | `0x2586e99` passes the returned vector to a cleanup boundary before unwind resumes. |
| Vector cleanup's panic helper | `0x250f469` can visit remaining rows through the selected row cleanup, then conditionally releases the vector backing before unwind resumes. |
| Remaining-row cleanup call during unwind | `0x250f4ab` calls a separate external boundary; `ud2` follows if it returns. |

These are exception-table and local-code observations, conditional on an exception taking the indicated landing pad. They do not prove allocator behavior, external helper cleanup semantics, OS effects or that an exception actually occurs.

### Inferences and unresolved questions

The exact bounded label and the matching consumer layout support a small-vault-summary query role; the names of the row fields, ownership types, request variant and full source signature are not established. A 20-byte comparison is observed, but calling it an account address would require separate evidence. The relationship between the default and discriminant 32 is imported from the earlier digest-bound constants packet, not inferred merely from the name bytes. The saved selector scenarios and lock models are synthetic deductions under stated memory and normal-return assumptions, not executions or a native behavior oracle.

## Implementation and comparison

Not yet implemented. There is no independent Rust component, Cargo manifest, build, raw/normalized body comparison, normalization mask, helper closure or whole-ELF identity claim. The target's helper functions, indirect dispatch behavior, allocator failure policy and all external effects are boundaries. No fixture derived from live state, private key or network activity is used.

## Results and limitations

The collector records 6 selected FDE extents totaling 3,290 bytes, 768 decoded instruction rows, 176 fixed instruction contracts, 89 direct branches, 54 call or indirect-transfer rows, 19 selected RELATIVE relocations, 8 name descriptors, 33 LSDA entries, 15 selected failure boundaries, 29 normal-flow propositions and 11 explicitly synthetic selector scenarios. These counts are for the selected extents and handoff only; they are not component or whole-node denominators.

The 57 focused tests passed with zero skips. They cover the entire name-byte and flag-byte domains, threshold equality and unsigned boundaries, all 20 key positions, all extra-flag byte values, the end-tag collision model, float/NaN and lock boundaries, cleanup guards and machine-width size wrapping, plus corrupted digest, bytes, branch target, section backing, descriptor, relocation, FDE and LSDA controls. Tests require the capture and do not skip when it is missing. All four `constants` progress gates remain false. The supplied open-PR metadata contains titles and file paths, not every PR body. Existing local work-items and available prior packets were searched for the six selected starts; unavailable PR bodies still require an address-overlap check by the submitting account. No target execution, integrated node build, behavior equivalence or hosted CI result is claimed.

Next question: establish the real input record variants and the previously indexed caller's request routing without duplicating its existing owner, then validate an independent implementation against separately authorized target-grounded fixtures.
