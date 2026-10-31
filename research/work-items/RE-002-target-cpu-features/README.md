# RE-002-target-cpu-features: Is AVX/BMI used outside runtime-dispatched paths?

- Component ID: build provenance (no catalogue component)
- Target releases and full SHA-256:
  - `artifacts/node/94/hl-node` `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  - `artifacts/node/115/hl-node` `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  - `artifacts/visor/captured/hl-visor` `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`
- Source commit: upstream `main` at `1f8c67c` (this packet's checkout). No reference source was used.
- Claim status: observation for the instruction census and class labels; inference for
  the `tzcnt_lzcnt` compatibility reading and the dispatch interpretation; unresolved
  items are listed under Results and limitations.
- Scope included: every decoded instruction inside every FDE-bounded range in the three
  targets, classified into CPUID, hard BMI1, hard BMI2, AVX, AVX-512, the
  `tzcnt_lzcnt` soft alias, and `vex_other`. Resolves the `target_cpu_features` row of
  [`RE-002-build-provenance`](../RE-002-build-provenance/README.md).
- Scope excluded: call-graph recovery, caller-side dispatch, Ghidra, execution of any
  target, rebuilding, and every other RE-002 unresolved field.

## Reproduce

Run from the repository root after `make pull` (or an LFS fetch):

```sh
make target-cpu-features
python3 tests/test_target_cpu_features.py
make doctor
```

`tools/target_cpu_features.py` refuses a target whose SHA-256 or size differs from
`provenance/artifacts.json`. It reads the files and never runs them. Standard library
only. Each target takes about 20 s (node #94), 25 s (node #115) and 3 s (visor) on the
recorded platform.

The capstone cross-check recorded below is packet-specific. To re-run it, `pip install
capstone` and use the inline script in this directory's history; the retained result is
`capstone-crosscheck.json`.

Recorded environment (this packet):

| Item | Value |
| --- | --- |
| Platform | macOS, darwin, x86_64 (Apple Intel) |
| Python | 3.13.12 |
| capstone (cross-check only) | 5.0.7 |
| Commands | as above, from the repository root |

Checks run and their exact outcomes:

| Check | Outcome |
| --- | --- |
| `python3 tools/target_cpu_features.py --release 94` | pass; writes census/functions/dispatchers under `work/target-cpu-features/94` |
| `python3 tools/target_cpu_features.py --release 115` | pass |
| `python3 tools/target_cpu_features.py --release visor` | pass |
| `python3 tests/test_target_cpu_features.py` | 15 tests, all pass (synthetic ELFs, no LFS) |
| `make doctor` | runs; reports missing gpg/Java/Rust on this host (pre-existing) |
| `make verify` | **not completed on this host.** SHA-256 and size checks pass for every materialized artifact (via `tools/artifacts.py check`). `gpg` and the pinned submodules are unavailable here; no signature or pin result is claimed. |
| `make catalogue-check` | **not completed on this host** (uninitialized `references/can1357-hl` submodule). This change adds no component or progress record. |

## Evidence

### Classification rules (observation)

| Class | Encoding | Requires the feature? |
| --- | --- | --- |
| `cpuid` | `0F A2` | n/a (feature probe) |
| `tzcnt_lzcnt` | `F3 0F BC` / `F3 0F BD` | **No.** These are the `rep bsf` / `rep bsr` aliases and execute as BSF/BSR on pre-BMI CPUs. |
| `bmi1` | VEX.0F38 `F2`/`F3` (andn, blsr, blsmsk, blsi) | **Yes.** VEX-only; no legacy form. |
| `bmi2` | VEX.0F38/0F3A (bzhi, pdep, pext, mulx, shlx, shrx, sarx, rorx) | **Yes.** VEX-only. |
| `avx` | VEX map 0F/0F38/0F3A SIMD opcodes | **Yes.** VEX SIMD requires AVX. |
| `avx512` | EVEX-encoded forms | **Yes.** |
| `vex_other` | VEX with an opcode that has no classified form | Not counted as AVX. |

A legacy `F3 0F 38 F6` is ADX `adox`, not BMI2 `mulx`; the tool keeps those in `other`.
`capstone-crosscheck.json` records a capstone 5.0.7 decode of a per-class sample at the
tool's site VAs: **0 disagreements** on all three targets (misses are sites where
mid-function capstone resynchronisation did not land on the VA; those are not scored).

### Census (observation; denominator = every decoded instruction in FDE-bounded ranges)

| Target | FDE records | `cpuid` | `bmi1` | `bmi2` | `avx` | `avx512` | `tzcnt_lzcnt` | `vex_other` | undecoded bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| node #94 | 121,299 | 28 | 4 | 935 | 3,440 | 90 | 14,652 | 5,501 | 400 |
| node #115 | 135,313 | 28 | 4 | 935 | 3,922 | 96 | 7,132 | 5,688 | 195 |
| visor | 11,028 | 10 | 0 | 0 | 610 | 5 | 2,230 | 510 | 19 |

### Function disposition (observation)

| Target | functions with hard ISA (`bmi1`/`bmi2`/`avx`/`avx512`) | of those, same-function `cpuid` | `cpuid`-only functions | functions with only `tzcnt_lzcnt` |
| --- | ---: | ---: | ---: | ---: |
| node #94 | 2,611 | **0** | 10 | 7,246 |
| node #115 | 2,608 | **0** | 10 | 3,066 |
| visor | 197 | **0** | 1 | 1,082 |

CPUID sites cluster in a handful of small functions (`dispatchers-94.json` lists 10
ranges of 27–31 bytes each for #94, e.g. `0x4ec4790`–`0x4ec47ab`). No FDE range that
contains a hard-ISA instruction also contains a CPUID.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no comparator against compiled code, no
call-graph recovery. The question is answered at the instruction-census level only.

## Results and limitations

Machine-readable metrics are in `census-*.json`; per-function class counts are in
`functions-*.json`; a 200-row sample of sites is in `sites-94-sample.tsv`.

**What the census establishes.** All three captured targets contain thousands of
VEX-encoded AVX instructions and (in the nodes) hundreds of BMI2 instructions. Zero
FDE-bounded functions that hold those instructions also execute CPUID. CPUID exists
only in a few dedicated, tiny functions.

**What the census does not establish.** Same-function CPUID is the only dispatch
signal used here. A dispatcher that calls a specialised leaf (the usual
`std::arch::is_x86_feature_detected!` shape) is invisible to this tool: the leaf would
still show `no_same_function_cpuid`. Distinguishing "unconditional baseline feature"
from "callee-side runtime dispatch" needs a call-graph or indirect-call analysis and is
the concrete next question. Jump-table desynchronisation and data-in-`.text` can
under-count; `vex_other` is a conservative residue and is not credited as AVX. FDE
extents are unwind-described ranges, not validated function boundaries. No gate is
requested for any catalogue component.

**Next question.** For each of the 10 node #94 CPUID functions, recover the call
targets and check whether any hard-ISA leaf is reachable only through them.
