# RE-002: Which stock Rust objects can carry the observed Clang RC2 stamps?

- Component: build provenance; no catalogue component or progress gate.
- Base source: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Targets: node #94, node #115 and visor separately. Full sizes and SHA-256 values are retained in `inputs.json` and checked against `provenance/artifacts.json` before binding.
- Requirement: the existing [RE-002 packet](../RE-002-build-provenance/README.md) explicitly leaves unchecked which input objects carry the Clang RC2 stamps.
- Result: authenticated stock carriers and one code-compatible builtin witness; **unique historical input/stamp origin remains unresolved**.
- Included: signed distribution metadata, tar/ar/ELF inventory, exact `.comment` carriage, bounded object/target code comparisons, static caller evidence and corruption controls.
- Excluded: captured execution, a recovered node/workspace, build flags, historical linker extraction, a complete target-function claim, and completion gates.

## Observations

The signed official Linux standard-library archives contain the exact Clang `21.1.0-rc2` / `22.1.0-rc2` strings seen in the respective targets. This is actual ELF `.comment` evidence, not a whole-file string-search attribution. Both manifests and archives passed detached-signature verification against the Rust release key published through Rust Forge. The empty verification keyring reports undefined ownertrust: identity comes from official HTTPS publication, not a separately certified web of trust. Raw successful status records and detached signatures are retained under `authentication/`.

| Release / Linux std archive | Compressed bytes | SHA-256 |
| --- | ---: | --- |
| 1.94.1, 2026-03-26 | 29,846,424 | `74109ee2c19098f1d7122087dd338a8f643203b3ce678c9d58169db733e17a03` |
| 1.95.0, 2026-04-16 | 29,573,972 | `047ea7098803d3500fa1072e9cee5392697e21525559e4458128a2bf874aa382` |

Each archive has 81 tar records, 74 regular files and 34 regular ar archives. The ar denominators include 68 name/symbol-table members: 1,063 / 1,064 total ar members, containing 995 / 996 ELF relocatable members. One additional standalone ELF shared object is counted separately. Paths, sizes and resource ceilings are checked; directory/other nonregular records are not followed, thin archives are excluded, and no archive member is installed or executed.

Exact RC2 carriage is **non-unique**: 675 / 676 relocatable members carry it. Each release includes 35 such `compiler_builtins` members, 20 `profiler_builtins` members and seven sanitizer/runtime archive groups. The final target `.comment` is a mergeable string section; neither its string count nor order identifies contributing objects.

The bounded code/data search covers the stamped relocatable members in the compiler/profiler libraries. It excludes relocated and undersized payloads rather than guessing relocation masks. Sanitizer/runtime groups are inventoried but not ruled out as historical inputs. Repeated zero-filled profiler data is not treated as an informative provenance binding.

## Exact code witness

Both signed versions' `compiler_builtins` contain member `45c91108d938afe8-popcountdi2.o`, symbol `__popcountdi2`. The complete 98-byte object symbol/executable section is relocation-free and has SHA-256:

`09027f7508488f9fabf097f96e8db1d2e2740cf931ae88d008e04df4a8ab2916`

| Target | ELF virtual-address window | File-offset window |
| --- | --- | --- |
| node #94 | `[0x5660010, 0x5660072)` | `[0x565f010, 0x565f072)` |
| node #115 | `[0x63f0960, 0x63f09c2)` | `[0x63ef960, 0x63ef9c2)` |
| visor | `[0x7a6720, 0x7a6782)` | `[0x7a5720, 0x7a5782)` |

The exact sequence occurs once in each target's file-backed executable sections, with no normalized operands. A separate Python reader of the GNU ar format, using pyelftools 0.32 for ELF records, agrees on all 110 compiler/profiler RC2-carrier member names, offsets, sizes and digests. Native Apple LLVM 21.0.0 statically decodes both object members and target windows into the same 27 instructions: a straight-line register/immediate computation ending in `ret`, with no calls, jumps, RIP-relative references, explicit data-memory operands or code relocations. The return still consumes the caller's return address. No code was executed.

No FDE covers these windows in any target. Raw `e8 rel32` candidates number 25 / 25 / 20; they are not a decoded xref census. One independently decoded caller FDE per target verifies a real call to the selected start:

| Target | Decoded call | Caller FDE interval |
| --- | --- | --- |
| #94 | `0x4f9eb9b` | `[0x4f9eb90, 0x4f9eba5)` |
| #115 | `0x5d3f1cb` | `[0x5d3f1c0, 0x5d3f1d5)` |
| visor | `0x719293` | `[0x719010, 0x719682)` |

These observations support an entrypoint inference and a bounded code witness. They do not turn the window into an accepted whole-function/body denominator.

## Falsification and interpretation

- One object code-byte corruption keeps its RC2 comment but loses every target code match.
- A comment-only corruption keeps the target code matches, demonstrating that code identity cannot select the producer stamp.
- Shifted coordinates, non-executable/NOBITS object sections and a wrong target digest are refused or fail their comparison.
- Both Rust releases have **identical witness code**, despite different member hashes and producer stamps. Code identity therefore cannot choose the historical Rust release or archive member.

The immutable Rust commits stamped in the targets pin LLVM commits matching the full target LLD strings. Their Linux distribution recipes explicitly build Clang RC2 and select it for C/C++ compilation. The corresponding `compiler-rt` source file is identical at both pinned LLVM revisions. URLs and source hashes are in `source-links.json`; no upstream implementation is copied into new Rust code. Upstream Rust and LLVM material retains its terms, including compiler-rt's Apache-2.0 WITH LLVM-exception license.

**Inference:** prebuilt Rust distribution objects are a demonstrated compatible route for the observed Clang stamps and selected code. The stamp alone does not establish the application's C compiler. **Unresolved:** which historical member was actually extracted, whether another carrier supplied the merged stamp, and the application's exact native build configuration.

Related open [PR #1024](https://github.com/lalalune/hyperliquid-source/pull/1024) already studies node #94's popcount behavior and callers while disclaiming source provenance. That work retains its attribution. This packet addresses the separate signed-distribution/object compatibility question across three captures; it does not claim new arithmetic behavior or its 25-caller proof.

## Reproduce

Python 3.10+ is sufficient for the offline analysis. GnuPG and curl are required only for the explicit input-acquisition command. It downloads about 59.4 MB from the pinned official authority, verifies signatures and hashes, and does not install components or run archive contents. Use fresh owned directories:

```sh
packet=research/work-items/RE-002-std-clang-carriers
python3 "$packet/fetch_inputs.py" --out work/re002-std-inputs
python3 "$packet/probe.py" --repo . --inputs work/re002-std-inputs \
  --out work/re002-std-results --native-objdump /path/to/llvm-objdump
```

The native-reader option must name an existing compatible LLVM objdump. Without it, the probe retains the static byte witness and labels undecoded caller candidates accordingly; it does not claim an installed disassembler. The recorded macOS run used `/usr/bin/objdump` (Apple LLVM 21.0.0). All default analysis is offline and original inputs remain unchanged. `expected-results.json`, `target-observations.json` and `object-controls.json` are byte-for-byte copies of the qualified native run's compact outputs. Native-reader identities may differ on another host. The supplementary independent method and its retained receipts are under `independent/`.

## Results and limits

This is partial reproducible RE-002 research. No gate is requested. No binary transplantation, inferred-source copying, invented dependency lock, model call, captured-target execution/networking, chain action, transaction signing, Linux-native build or whole-node equivalence is established. The explicit official HTTPS input acquisition is separate from the offline analysis.

`make doctor`, `make verify`, `make catalogue-check` and `make reproduce` passed. `make test` ran 357 tests with 4 failures, 12 errors and 15 skips: the same 16 failure/error identifiers as the independently observed identical base on this macOS host. Missing GNU readelf and Apple objdump formatting/decoding expectations, including dependent setup errors, leave the full suite non-green. `validation.json` and `test-failure-comparison.json` retain the results and limits. All 45 artifact/import identities and seven pinned references remained unchanged. A green tooling subset is not reconstruction evidence.

Next question: can an authentic historical linker map/extraction record, or a discriminating member-specific code/data witness, select the actual carrier rather than merely a compatible stock object?
