# RE-015: name-selected factor in a scheduled observer

Node #115 uses the configuration name byte to choose a binary64 factor that reaches a scheduled observer cell: for the established `NvTestnet` tag the initializer's binary64 0.1 becomes 0.5, while the `NvMainnet` tag yields 0.1, so a reconstruction must apply the release-specific tag mapping before initializing this cell.

- Component ID: `constants`, task RE-015; the scheduled observer is a bounded consumer of global configuration, not a claim of ownership of all scheduling code.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is a lead only. No reference code is copied.
- Claim status: observations are the authenticated ELF bytes, FDE and LSDA records, relocation addends, selected control transfers and object-relative stores. The associations between names and runtime tag bytes use the separately established #115 classifier evidence; source-level purpose and helper effects are inferences or unresolved.
- Scope included and excluded: a poll wrapper, its scheduled-observer poll body and keyed lookup, a related lazy-cell initializer and two callback candidates, the observer constructor, the configuration-byte factor selector and its cleanup helper. The generic once implementation, shared observer-update implementation, allocator, dynamic callees, complete polling graph, all JSON input cases, concurrent interleavings and runtime effects are outside this packet. No component gate is requested.

## Reproduce

From the repository root, Python 3.12.3 on Linux x86-64, with the authenticated #115 artifact present:

```sh
python3 tools/node115_scheduled_factor.py --out research/work-items/RE-015-scheduled-observer-115
python3 -m unittest tests.test_node115_scheduled_factor
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-scheduled-observer-115 && sha256sum -c MANIFEST.sha256)
```

For the determinism comparison, replace the placeholders with two distinct empty, writable repository-root-relative directories:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/node115_scheduled_factor.py --out <tmp-dir-one>
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/node115_scheduled_factor.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The producer and tests use only Python's standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. The complete #115 size and digest are checked before parsing and before output is written. ELF sections, FDE/CIE records, the unwind index and ULEB128 are read through those shared modules. File mapping rejects SHT_NOBITS, unallocated, ambiguous and out-of-file ranges. The producer checks fixed instruction byte windows and decodes only the selected relative calls and conditional branch forms; it is not a general x86 decoder. GNU objdump 2.42 was used separately for bounded human inspection and is not invoked or parsed by the producer or tests. No captured executable, network, chain, key or personal runtime state is used.

For the optional historical comparison, if the separate #94 capture is available at the reference location, run:

```sh
python3 tools/node115_scheduled_factor.py --out <tmp-dir-one> --compare-94 references/can1357-hl/bin/hl-node-mainnet-new
```

The optional comparison verifies the complete #94 digest independently and prints a name-matched comparison. It does not change the 16 generated #115 files. #94 is not required by the default producer or by the focused tests. The prior #94 record is `RE-015-lazy-name-factor-94` in repository history; its digest is `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. It did not analyze this #115 observer caller.

## Evidence

All addresses below are linked ELF virtual addresses, before runtime rebasing. `functions.tsv`, `windows.tsv` and the other records also carry file offsets. FDE ends are unwind-described half-open extents; they are not by themselves a complete function census. Selected bodies are retained in `bodies.tsv` with hashes, while individual semantic claims are tied to fixed bytes in `windows.tsv`, `branches.tsv`, `calls.tsv`, `relocations.tsv` and the tables. Unsupported instructions are not silently assigned a meaning. The LSDA rows retain action indices but do not interpret the action chains.

| Selected FDE | Bounded role established by the selected bytes |
| --- | --- |
| `0x15fe340..0x15fe45c` | Wrapper that calls the poll body and has a separate nonzero-state failure route. |
| `0x15ed290..0x15ed954` | Four selected state destinations, name-prefix gate, optional keyed update, guarded global update, terminal/pending states and local cleanup. |
| `0x15543f0..0x155474d` | Key-length dispatch, byte-comparison boundary and the hit/miss return conventions consumed by the poll body. |
| `0x15edb90..0x15edbe9`, `0x15ea1e0..0x15ea239` | Two relocated callback candidates that clear a context pointer, invoke an initializer and copy the returned cell. |
| `0x15d86b0..0x15d8722` | Initializer for the selected cell; supplies a concrete label, value and flags to the constructor. |
| `0x1548bb0..0x1548f3d` | Constructs the observer, normalizes a name-scaled binary64 product, writes fields and has allocation, time-conversion and unwind paths. |
| `0x15474d0..0x1547529` | Reads the configuration byte and indexes the factor table after a guard check. |
| `0x154f790..0x154f846` | Cleanup helper called by selected constructor landing pads. |

### Entry, prefix gate and state transitions

The wrapper calls the selected poll body at `0x15fe3d7`. Its entry reads a byte at input offset `+0x280` and indexes four signed-relative slots at `0x46a064`; the selected slots are `0 -> 0x15ed2c3`, `1 -> 0x15ed2ee`, `2 -> 0x15ed2e1`, and `3 -> 0x15ed668`. The local dispatch has no demonstrated check for bytes outside these four values; the table is not claimed to define behavior for other values. State 0 performs a locked increment and takes `ud2` if the resulting signed condition is nonpositive. States 1 and 2 reach distinct helper-call sequences. Their internals and whether they return remain boundaries.

On the selected measurement route, `0x15ed3be` requires an input length of at least 24, and `0x15ed3d6..0x15ed3f3` compares all 24 bytes against data at `0x455fe0` and `0x451560`: `tokio_scheduled_observer`. A longer input with those first 24 bytes passes this local gate. `prefix-model.tsv` records six abstract controls; it does not execute target instructions. A short or different input takes the direct global-cell route. A matching input first enters the keyed path, then also reaches the global route after the selected unlock.

On the keyed path, `0x15ed481` calls `0x15543f0`. That body dispatches key lengths into 0..3, 4..7, 8..16 and at least 17, then uses selected hash and control-byte operations. A candidate must have matching length at `0x15545cc` before the comparison at `0x15545f3`. The register-indirect comparison target is loaded from slot `0x64df9f8`; the ELF dynamic relocation and symbol tables bind that slot to `bcmp`. A zero return takes the hit route at `0x155465c`. Under the standard `bcmp` contract this supports a byte-equality interpretation, conditional on the runtime binding honoring that contract.

The hit route stores a pointer at result `+8` and signed-minimum at result `+0`, then conditionally releases the supplied key. The poll's `0x15ed496` detects that sentinel and derives the selected existing value pointer without calling the constructor. On the miss route, a zero field at map `+0x10` invokes the growth boundary; the body then copies the supplied three-word key and returns map/hash context. The poll calls the observer constructor at `0x15ed4ca`, prepares a 608-byte payload, writes the selected slot and copies the payload at `0x15ed596`; it also updates table control and count fields. `lookup-lengths.tsv` gives eleven synthetic boundary cases; `dynamic-symbol.tsv` retains the relocation and symbol coordinates. This establishes these selected hit/miss conventions, not the full hash algorithm, map ABI, feasibility of every path or complete value lifetime.

The poll body uses a second, global route beginning at `0x15ed5fe`. It loads `0x64e1850`, whose RELATIVE relocation points at cell `0x64f0428`, then checks its word at `+0x268`. A nonzero guard calls the shared once boundary and normally rejoins the local lock attempt. The file's initial guard bytes encode 3; that is a file observation, not a runtime guard state. The local locked compare-exchange attempts to change the cell's first byte from 0 to 1; the failed acquisition and release cases call separate contention boundaries. After acquisition, `0x15ed63a` passes `cell+8` and the locally calculated numeric argument to the observer-update slot, and then attempts to release the cell. That update slot is already mentioned by `RE-001-node115-latency-projection`; its implementation is not claimed as newly reconstructed here.

When the selected child returns nonzero at `0x15ed67a`, the poll stores state byte 3 at `+0x280` and returns 1. The selected terminal marker route releases references, stores state byte 1 and returns 0. The LSDA entry covering the global observer call points to `0x15ed8d3`, which attempts the corresponding unlock; the local unwind continuation releases selected references, stores state byte 2 and calls the unwind boundary. These describe local machine-code consequences conditional on external returns and unwinding, not actual scheduler behavior or a proof of lock correctness.

### Lazy cell, name factor and initialized value

The guard call supplies a vtable header at `0x6401cf8`; its first three qwords are 0, 8 and 8. RELATIVE slots at `+0x18` and `+0x20` bind the two callback candidates in the table above. Each callback clears its supplied context slot, rejects a null pointer or a state byte equal to 1, and otherwise calls through the first word of the cell. If that call returns normally, it copies 616 bytes into the cell, ending immediately before the guard. The callback and vtable bindings are observations; the generic once helper's complete dispatch and interleaving semantics remain a boundary. In the captured file, a RELATIVE relocation binds the cell's initial first word to initializer `0x15d86b0`.

That initializer supplies the 29-byte label `tokio_spawn_forever_scheduled`, a binary64 input whose bits are `0x3fb999999999999a`, and a flag byte 1 to the observer constructor. The conventional decimal rendering of the input is 0.1. The constructor calls the factor selector through a RELATIVE slot, multiplies the input in `xmm0` by the selected value and writes the normalized result at constructor output offset `+0x218`. The wrapper writes its own leading byte and copies 608 bytes of the constructed payload to output `+8`. Consequently, if the selected callback initializes this file-initialized cell and the calls return normally, that product occupies cell offset `+0x220`, linked VA `0x64f0648`. This does not claim that publication is atomic or that the cell is actually initialized in a particular execution.

The selector reads byte `+0x48` of the configuration cell via RELATIVE slot `0x64e0918 -> 0x64f06c0` and reads eight bytes from `0x4671d0 + 8*byte`. Its local selected entry has no range check. The #115 `variant index 0 <= i < 79` diagnostic and two independently relocated 79-entry name-descriptor arrays agree on all names. They establish the recorded data correspondence; assigning an input spelling to a runtime byte additionally relies on the separately traced #115 name classifier, and is not re-proved by these arrays alone. Within that domain, 18 table entries are binary64 1.0 and 61 are 5.0. `factor-runs.tsv` records all 17 contiguous runs without resubmitting the historical name table.

| #115 contextual name | Tag/index | Selected factor | Initialized product under ordinary binary64 arithmetic |
| --- | ---: | ---: | ---: |
| `EaTx` | 13 | 1.0 | 0.1 |
| `NvTestnet` | 33 | 5.0 | 0.5 |
| `NvMainnet` | 35 | 1.0 | 0.1 |
| `DummyNv` | 39 | 5.0 | 0.5 |

The product model operates on the bits **after** `mulsd`. For those bits, the selected branch sequence preserves positive finite values and both signed zeros, maps negative nonzero finite values to positive zero, and maps infinities and NaNs to positive zero. Subnormal boundaries and both NaN signs are included in `product-model.tsv`. The model assumes normal helper returns and does not establish floating-point exception handling, nondefault rounding modes, flush-to-zero settings or what the input value means. The tool rejects index 79 as an analysis-domain check; this is not a target-side rejection.

### Failure paths and release comparison

A constructor input length with the sign bit set, or an unsuccessful nonempty allocation, reaches an allocation-failure boundary and then `ud2` if that boundary returns. A zero result from the selected time-conversion call reaches the 43-byte diagnostic at `0x465ab7`, an error boundary and then `ud2` if that boundary returns. The LSDA entry covering the factor-selector call reaches `0x1548ed4`, where selected temporary cleanup calls and buffer cleanup precede the unwind boundary. The callbacks' null-pointer branches call one failure boundary and then the state-failure boundary if the first returns; the next byte after each selected FDE is `cc`. These conditional continuation statements do not assume any failure helper actually returns.

The #94 leads remain bound to their original digest: full `/cham` and `/static_config` entries were at `0x1fc0ec` and `0x1ef5f5`; #115 independently has them at `0x44ab69` and `0x4401ef`. For `NvTestnet`, the #94 descriptor at `0x5668488` points to text at `0x2180ff`; the #115 descriptor at `0x6410ef8` points to text at `0x481e30`. The selected #94 factor load was `0x1402767` and its table was `0x218640`; the #115 load is `0x15474e7` and its table is `0x4671d0`. The optional comparison reads both ELF files and RELATIVE descriptors directly. It finds the same factor for each of the 76 names common to the two selected arrays, but 63 names have moved indices and 14 of the first 76 ordinal factor positions differ. For example, old index 13 selects 5.0 for `HeavyTestnet`, while #115 index 13 selects 1.0 for `EaTx`. This is a comparison of the selected tables, not proof of whole-release equivalence. The two configuration templates and the #115 name classifier were already addressed by other work; their function bodies are not selected here.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler and linker settings, two-build comparison, runtime fixtures, raw or normalized binary comparison, and whole-ELF equivalence are **not yet implemented/measured**. There are no comparison masks. Generic once, observer-update, allocation, vtable, external-call and data closure remain separate gaps.

The focused collector is needed for this active RE-015 question: the shared ELF/FDE parsers do not connect these selected instruction encodings, callback slots, factor values and LSDA entries, while the requested evidence must regenerate without a native disassembler. It leaves the common parsers unchanged.

## Results and limitations

The output contains 9 selected FDE extents totaling 4,349 bytes, 49 fixed byte windows, 61 selected conditional branches, 32 selected calls, 10 selected RELATIVE relocations and 43 LSDA call-site rows. It also contains 79/79 name-array agreements, 17 factor runs, 13 synthetic product cases, 6 synthetic prefix cases and 11 synthetic key-length cases. These are selected static facts and model cases, not instruction coverage or a whole-component denominator.

Thirty-six focused unittest cases passed with zero skips, including damaged digest, branch, call, instruction, relocation, template, factor table, name descriptor, exception header, prefix, lookup length, dynamic symbol and diagnostic controls, plus ambiguous, NOBITS and out-of-range mappings. One independent bit-level oracle checks 16,384 sign, exponent and fraction-boundary combinations. Two generations with different hash seeds and time zones matched byte for byte under a Python-only PATH. Artifact verification, catalogue consistency and inventory reproduction passed; repository-wide test discovery was not run under the specified memory limit.

The generic once call is a boundary, so this packet does not prove which callback executes in every state or that a given runtime process actually uses a particular name. It does not recover every branch and helper of the selected poll body, all map replacement behavior, complete float-environment behavior, a Rust build or any whole-component gate. Next question: identify an unowned #115 downstream consumer of the initialized field and determine whether its writes can be tied to this poll path without reselecting the shared observer helper.
