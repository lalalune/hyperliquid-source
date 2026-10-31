# RE-002: require file-backed sections for section-attributed facts

Question: can NOBITS metadata lend unrelated physical bytes to exact build-provenance facts? Scope: tools/build_provenance.py, its regression, and this packet. Base: 1f8c67c63ca4794c9689235471c60297f8a5c985. No reference-source semantics are used.

Input: retained Linux x86-64 node #94, SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f. The regression hashes the complete capture first. It changes only sh_type to SHT_NOBITS (8) for .comment, .interp, .dynamic, and .dynstr, one at a time in owned memory. Coordinates are section-header table file offsets e_shoff + e_shentsize * index + 4. Capture files, original payloads, and pins are unchanged; no transformed input is executed or claimed loader-consistent.

Observation: base derive() accepts all four corruptions and consumes the old physical bytes as section contents. Four assertRaises subcases fail. NOBITS has no file-backed contents, so those section-attributed exact facts are unsupported. The common section_bytes helper now rejects NOBITS before slicing. This does not prohibit whole-file byte-pattern observations, establish runtime behavior, or authenticate signatures.

Reproduction (Python 3.12.14, Windows, PYTHONUTF8=1 and PYTHONIOENCODING=utf-8):

```text
python -m unittest discover -s tests -p test_provenance_file_backing.py -v
python -m unittest discover -s tests -p test_build_provenance.py -v
python tools/build_provenance.py --check 94 115 visor
python -m unittest discover -s tests -v
python tools/doctor.py
python tools/artifacts.py verify
python tools/verify_imports.py
python tools/catalogue.py --check
python tools/reproduce.py
git diff --check
```

Before: new regression has four failing corruption subcases. After: one new test passes; existing nine provenance tests pass; all stored provenance records for authentic #94, #115 and visor pass --check unchanged. The latter uses their full identities from provenance/artifacts.json, not reused #94 coordinates.

Full baseline 281 tests and changed 282 tests both report seven failures, 32 errors, nine skips on this host. Full tooling is not green. make is absent, so its Python commands were run directly. Doctor lacks GPG/native analysis/Rust tools. Artifact hashes pass before missing GPG blocks signature checking. Import verification fails at the incomplete Windows can1357 checkout (reserved node/aux.rs); catalogue-check is stale and reproduce stops at artifact verification. Transient original logs are retained outside the contribution, including provenance-backing-before.log, provenance-backing-after.log, provenance-backing-existing.log, provenance-backing-records.log, provenance-backing-full.log and backing-*.log.

Inference is limited to file-content attribution. No recovered Rust, binary equivalence, complete provenance recovery, or component gate is claimed. Next: maintainer reproduction on a complete supported checkout. All progress gates remain false.
