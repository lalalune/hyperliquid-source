# RE-001: build-name input guards and signed boundary condition, node94

Component: foundation/static seed and source-location validation. Question: which local predicates select retry/diagnostic paths before and during name processing? The maintainer's RE-001 task requests target-bound ranges and xrefs. This is a static research packet, not a reconstructed argument parser or a live defect.

Target: node #94, 91,774,280 bytes, SHA-2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f. Base1f8c67c63ca4794c9689235471c60297f8a5c985. Pinned can1357 build_mode.rs at999556f6e0a474b8312db96ec3149e1c44e97c23 is a lead only, with no inferred code copied. Its seed143ef30 and source-coordinate descriptions did not establish these guard paths. The actual source records give29:17 and32:26, not the reversed coordinate order in the lead.

Relation to prior work: PR42 covers the separate699-byte build-directory routing FDE13cd410..13cd6cb. This packet covers143ef30..143f4e7 and does not repeat its debug/release/run-client routing. A prepared overlapping route packet was discarded before submission, not counted. PR428's path/sort guard is another FDE13ca0e0, not this one. Live topics and PR42 discussion were checked; no claim of whole-component ownership is inferred.

## Original evidence

Complete FDE-described scope VA0x143ef30..0x143f4e7, end exclusive:1,463 bytes,353 Capstone5.0.6 instructions, body SHA-25635744d99bdfa9937839e55ef17390c8138467f81205f9622eb188f13b1b93f33. records.json retains full original body/FDE/CIE, source records, controls and coordinates. The native export is complete and contiguous, regenerated from each original byte rather than from prose. This is not a complete function or caller census. File mappings are derived from unique file-backed section coordinates; no runtime rebase is assumed.

Observed predicates and destinations:

- Length below2 bypasses the first-two-byte load. Otherwise two leading0x2d bytes select the iterator-loop route at143f1ee, before the selected predicate call.
- The direct predicate at143f009 ->1440df0 receives the exact six bytes /cham/ as its first slice and the current slice as its other arguments. A zero AL result takes the fallback at143f150. The helper's substring/prefix semantics are not assumed or reconstructed.
- On the nonzero-predicate route, empty length avoids a final-byte load; a final0x2f byte selects143f420 and the source-linked diagnostic. The37-byte diagnostic text is exactly `assertion failed: !arg.ends_with('/')`. Location566a0a8 binds base/src/build_mode.rs:29:17.
- After the local split-position bounds check, the byte comparison at143f120 uses immediate0xc0 and the branch at143f125 is signed JL to143f451. It tests exactly byte values0x80..0xbf, not all unsigned values below0xc0. Location566a090 binds32:26. Both pointer slots are originally zero with type8 RELA addends to the exact51-byte captured source path at200676.

The isolated CMP/JL truth table uses x86 subtraction sign/overflow flag equations, independently compared with `(byte &0xc0)==0x80` for all256 bytes (64 rejected). Intel SDM Vol1, conditional jumps table, defines signed JL by SF xor OF: https://cdrdv2-public.intel.com/819711/253665-sdm-vol-1.pdf . This is an architectural calculation, not execution of captured code or a test of whole input admission. Without a valid original UTF8 string, that single-byte condition is not a full UTF8 validator. The full slash scanner, suffix processing, iterator, formatting and returned name remain unresolved.

## Reproduce

Windows/Python3.12.14, PYTHONUTF8=1, PYTHONIOENCODING=utf-8; repository root:

```text
python tools/build_name_guards.py --check research/work-items/RE-001-build-name-guards-94/records.json
python -m unittest discover -s tests -p test_build_name_guards.py -v
python research/work-items/RE-001-build-name-guards-94/verify_native.py
python -O research/work-items/RE-001-build-name-guards-94/verify_native.py
python -m unittest discover -s tests -v
python tools/doctor.py
python tools/artifacts.py verify
python tools/verify_imports.py
python tools/catalogue.py --check
python tools/reproduce.py
git diff --check
```

Regular analyzer/tests are stdlib only. Optional native replay uses Capstone5.0.6 on PYTHONPATH. Actual official Windows wheel capstone-5.0.6-py3-none-win_amd64.whl SHA-256761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064 was verified against https://pypi.org/pypi/capstone/5.0.6/json before loading. No dependency/lockfile/build-hook changes, captured target execution or filesystem calls through the captured code.

## Results and gaps

Six focused tests pass: exact report reproduction;12 instruction and five literal/path/Location corruptions below the identity gate; two scoped RELA retargets; altered capture digest; all256 isolated byte-condition cases; complete retained native-export byte coverage. --check passes. Native replay normal/-O is byte-identical:353 instructions/1,463 bytes. The isolated model adds no target execution/equivalence claim. Before the packet these local guard/coordinate bindings were unverified leads; this supplies original target evidence rather than changing the reference. Raw transient logs are retained under build-name-* outside the contribution.

Full baseline281 and changed287 tests both have seven failures,32 errors,nine skips; final elapsed117.619s. Full tooling is NOT green. make is absent, so its Python commands were attempted. Doctor lacks GPG/native analysis/Rust tools. Artifact hashes match before missing GPG stops signature verification. The partial Windows reference checkout (reserved node/aux.rs) blocks imports; catalogue-check is stale and reproduce stops at artifact verification. git diff --check passes. Native Capstone does not make the missing prerequisites pass; no hosted CI/container result is claimed.

No whole BuildMode API, complete name extraction, argument domain, filesystem behavior, recovered Rust, progress gate or equivalence is claimed. Captures/imports/pins/generated catalogues stay untouched. Machine-code excerpts retain artifact rights; new tooling/text is independent. Next: validate the predicate/iterator and remaining string-processing paths before claiming complete parser semantics.
