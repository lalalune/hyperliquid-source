# RE-002: Does an absent static symbol table imply absent debug information?

- Component: build provenance tooling; no native component gate requested.
- Target context: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference source: none used; this tooling and its fixtures are independently authored.
- Claim status: observed section presence; corrected metadata inference; the
  historical stripping command remains unresolved.
- Included: `tools/build_provenance.py` stripping inference, four ordinary ELF
  section-state controls, regression tests and preservation of the node #94 record.
- Excluded: recovered node implementation, compiler-profile recovery, function
  ownership, behavior comparison and any execution of generated or captured ELFs.

## Reproduce

With Python 3, a host C compiler and GNU strip/readelf available, run from the
repository root with a new work directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B research/work-items/RE-002-strip-inference/probe.py \
  --repo . --work work/strip-inference-controls
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_build_provenance.py -v
PYTHONDONTWRITEBYTECODE=1 make doctor verify test catalogue-check reproduce
```

The probe writes only its new owned work directory. It compiles a one-line C
fixture and statically inspects it; it never invokes a generated ELF or a
captured target. `-fdebug-prefix-map=<work>=/fixture` removes the temporary compile
directory from DWARF, and `--build-id=none` avoids an unrelated build-ID input.
The recorded runs used GCC 14.2.0 and GNU binutils 2.44. Other compiler versions can
produce different fixture bytes; the recorded hashes bind these observed inputs,
not an assertion that every host produces identical fixtures.

`before.json` and `after.json` contain exact commands, tool versions, SHA-256,
section-table observations, raw readelf output and classification records.
`<work>` in those commands is the new directory selected by `--work`; it is their
working directory. All four fixture hashes are identical between these two runs.
No fixture executable is committed.

## Evidence

GNU strip's ordinary `--strip-all --keep-section=.debug*` produces a valid ELF
without `.symtab` while retaining six nonempty debug sections. GNU readelf decodes
one DWARF compilation unit from it. The six sections are `.debug_abbrev`,
`.debug_aranges`, `.debug_info`, `.debug_line`, `.debug_line_str` and `.debug_str`.
Their file offsets and sizes are retained in each case's `sectionEvidence` and
in the raw section-table command output. These are fixture file coordinates,
not node addresses or inferred function bounds.

| Observed fixture | `.symtab` | Debug sections | Base conclusion | Corrected conclusion |
| --- | --- | --- | --- | --- |
| Unstripped | present | six | not stripped, with contradictory absence reasoning | not stripped, with presence reasoning |
| Symbol-stripped, debug retained | absent | six | symbols and debuginfo removed | static symbols absent; debug sections retained |
| Fully stripped | absent | none | symbols and debuginfo removed | unchanged |
| Debug stripped, symbols retained | present | none | not stripped, with contradictory absence reasoning | not stripped, with presence reasoning |

The exact section facts already distinguished these states. The prior inference
used only `elf.has_symtab` and supplied the same absence explanation for every
state. The correction consults `elf.debug_sections` as well and makes each
explanation agree with the observed section state. It does not identify whether
Cargo, a post-link strip tool, or another process produced a target's state.

## Implementation and comparison

The production change is confined to `interpret()`; ELF parsing, artifact
validation and fact extraction are unchanged. Two new deterministic regression
methods fail on the original helper. The fixed provenance suite passes all 11
methods, including the existing tests that authenticate all three separately
identified captures and reproduce their committed provenance records. Unit
controls use a minimal valid DWARF 4 compile unit and need no compiler or LFS input.
The real GCC/readelf probe independently establishes the ordinary ELF case.

`node94-unchanged.json` authenticates the node #94 digest and binds the original
section-header table at file offset `0x5785508`. Its entire regenerated provenance
record remains byte-identical to the committed record, SHA-256
`ec666ce9aec679a943908b7ead1efe0fbb4965268a63d271b8e68f9685e1a864`.
The node has neither `.symtab` nor debug sections, so its existing inference is
unchanged. No #94 addresses or labels are transferred to #115 or visor.

## Results and limitations

- Original required checks: `make doctor verify test catalogue-check` passes,
  including 431 tests, artifact signatures, imported files and pinned references.
- New negative controls: both methods fail against the unchanged baseline helper;
  the fixed focused provenance suite passes 11 tests.
- Ordinary ELF controls: four states, identical fixture hashes before/after;
  the partial-strip case retains one independently decoded DWARF compilation unit.
- Node #94: full saved provenance record unchanged. Captures, references, imports,
  generated catalogues and every component progress gate remain unchanged.
- Final required checks also include `make reproduce` because an inference rule
  changes; exact tested head and final check results are recorded in the PR.

Section presence is not proof of complete usable debugging information or of a
particular historical stripping command. This packet establishes a provenance
reporting correction and preservation of current target evidence. It establishes
no recovered Rust behavior, byte-identity gain, or completed native component.

Next question: which independent object-level evidence identifies the original
stripping step, beyond the final target's section inventory?
