# Static validation of the rmp-signable layout correction

Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Original repository revision: `05bc2de303c05525b71e7e257426e741bc66a390`.

The original producer treated a conditional 20-byte copy as unconditional and mislabeled the constructor-result continuation value as an error sentinel. The correction records the equality continuation and all four suffix lengths: 9, 18, 29 and 38 bytes. These lengths are additions to an unresolved helper-produced prefix.

| Retained actual run | Result | What it establishes |
| --- | --- | --- |
| Original ten-test suite | 10 tests passed, exit 0 | The old suite did not expose the defect. |
| Original-schema static reproducer | Exit 1; two of four length cases contradict the producer; four of four branch polarity changes go undetected | Concrete before-fix evidence, using authenticated native bytes only as data. |
| Unchanged final suite on an isolated baseline snapshot | 15 test methods, exit 1; 15 failure entries including subtests and 4 errors | The same final tests reject the old producer/records. See the classification below. |
| Final corrected suite | 15 tests passed, exit 0 | Corrected records regenerate; the four deciding edges, their destinations and exact widths are checked, with source/cursor and existing controls. |

The final source contains 20 mutated-byte checks and a separate wrong-public-identity check. Successful subtests are not individually printed by unittest; these counts come from the reviewed test source. The fifteenth method rejects the same-target near-JNE encoding that would change the optional branch's fallthrough. The first review and its finding remain privately retained; the final review found no remaining actionable issue in this bounded correction.

The final test file is byte-identical in the baseline and corrected runs (SHA-256 `d1f2b9ef337bb42a85714af72305deb1aacfe587eb425bf87e93fda3fa614c93`), with identical recorded arguments/environment and the same 15 methods. The isolated baseline snapshot contains ten original producer/dependency/packet files and that final test file. The baseline run reports one encoding-width failure, eight deciding-edge subtest failures and six prefix/cursor subtest failures; the four errors are missing old-schema keys (`continue_head`, `branches`, `suffix_bytes`, `condition`). These are **15 failure entries and 4 errors across 15 methods, not 19 methods**. The schema errors alone are not the behavior proof: the old-schema probe independently records two incorrect lengths and four undetected branch flips.

The corrected run completed before the later isolated baseline replay; exact timestamps preserve that chronology. No baseline-run order is invented. Repository-wide required checks and publication are outside this local-validation record.

## Evidence and reproduction

`validation.json` binds actual commands, times, exits, source identities and exact original/portable log hashes. `validation-logs.txt` contains all eight stdout/stderr streams with explicit section framing. Only the isolated-baseline stderr required a path substitution: its absolute snapshot prefix becomes `<BASELINE_SNAPSHOT>`, leaving failure text, source lines and counts intact. The other seven streams are verbatim; receipt command paths are projected to named placeholders. Exact private originals remain retained, and the deterministic substitution policy is recorded in the JSON. The compact final review is a projection bound to the original review hash, not a claim that the private audit file itself is published.

`reproduce-baseline.py` is the exact script used for the retained exit-1 probe. Run it only against the original revision with its authenticated node #115 input and reviewed static prerequisites:

```sh
python3 -B reproduce-baseline.py /path/to/original-checkout
```

Exit 1 is the expected defect observation. It uses the original `payload_bytes` schema; it is **not** a post-fix comparator. For the correction, use the repository's actual final focused test file:

```sh
python3 -B -m unittest discover -s tests -p 'test_rmp_signable_layout_static.py' -v
```

These are reproduction instructions, not additional executed commands in this local-validation record. GNU `readelf`/`objdump` and the authenticated target are required by the existing producer/test path. The target is read and disassembled, never executed.

## Limits

The suffix relation retains valid disjoint memory, stable source fields, nonwrapping spans and successful growth/helper preservation premises. Initial-prefix contents, allocation failure, unwind behavior, opaque assembly and a complete signing-preimage contract remain unclosed. No full-node equivalence, full `make test`, hosted CI or publication is claimed. All native observations and review receipts share one project and captured-target lineage.
