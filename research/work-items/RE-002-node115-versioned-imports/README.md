# RE-002: node #115 named versioned-import bindings

- Component/task: RE-002 build provenance (dependency identity only).
- Target: `artifacts/node/115/hl-node`, 105896032 bytes.
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source revision: `a8616af9432b8d8517b2af677880e117b7c28ef3`.
- Claim status: static observations; runtime compatibility remains unresolved.
- Scope: three imports carrying GLIBC_2.39 or GLIBCXX_3.4.30. No target execution,
  runtime linking, first-party semantic claim, reconstructed code, or completion gate.

## Question and existing evidence

`tools/build_provenance.py` records maximum version strings from `.dynstr`; its
build-host inference says the newest GLIBC symbol version "required is 2.39".
That does not identify the symbols or distinguish symbol binding from version
requirement flags. This packet supplies that bounded join, not a new build lock
or a claim that the Ubuntu build-host inference is false.

The existing `RE-002-node115-libstdcxx-abi` packet supplies section geometry,
version-need owners and a full-table census. The existing RE-012 pidfd query and
spawn packets and `RE-015-build-selection-115` already cover optional pidfd
paths and weak `pidfd_spawnp`; those results are not claimed as new here.
The new tool reuses the independently authored foundation ELF reader and adds
named dynsym/versym/vernaux joins, exact coordinates and retained version flags.

## Reproduce

From the repository root, with the authenticated node #115 LFS input materialized:

```sh
python3 tools/re002_node115_versioned_imports.py --check
python3 tests/test_re002_node115_versioned_imports.py -v
readelf --wide --dyn-syms artifacts/node/115/hl-node
```

`scoped-run.json` records the actual Python/platform/readelf versions, commands,
exit codes, timings, scoped test output and input/output SHA-256 hashes. All
recorded commands exited zero; seven tests ran and passed. GNU readelf 2.40
independently agrees on the three selected names, bindings and version indices;
`readelf-crosscheck.txt` retains only those lines, not the full table.
The target is only read; mutation controls operate on memory, never on its file.
No network, signing or target execution is involved. This scoped run does not establish repository-wide or independent validation;
consult the pull request validation record for those separate outcomes.

## Evidence

The reader validates 510 dynamic symbol entries, 510 version halfwords and 498
version-index carriers, then selects all carriers of the two stated versions.
Exactly three rows match that explicit denominator. All are undefined FUNC
symbols. Numeric offsets below are hexadecimal; VA means the unrebased ELF
virtual address, not a runtime address. Complete fields including string offsets,
version hashes, symbol sizes and visibility are retained in `evidence.json`.

| dynsym index | name | binding | version index | owner/version | dynsym file offset / VA | versym file offset / VA | vernaux file offset / VA | version flags |
|---|---|---|---|---|---|---|---|---|
| 140 | `pidfd_spawnp` | WEAK | 20 | `libc.so.6` / `GLIBC_2.39` | `0x1060` / `0x1060` | `0x3428` / `0x3428` | `0x3aac` / `0x3aac` | `0x0` |
| 168 | `pidfd_getpid` | WEAK | 20 | `libc.so.6` / `GLIBC_2.39` | `0x1300` / `0x1300` | `0x3460` / `0x3460` | `0x3aac` / `0x3aac` | `0x0` |
| 286 | `_ZNSt18condition_variable4waitERSt11unique_lockISt5mutexE` | GLOBAL | 44 | `libstdc++.so.6` / `GLIBCXX_3.4.30` | `0x1e10` / `0x1e10` | `0x354c` / `0x354c` | `0x384c` / `0x384c` | `0x0` |

## Interpretation and controls

Both GLIBC_2.39 symbols are weak, **but the shared GLIBC_2.39 version-need
auxiliary record has flags zero**. In particular its VER_FLG_WEAK bit (0x2) is
not set. A weak undefined symbol and a weak version requirement are different
ELF facts. The optional call paths and weak bindings therefore do not prove
that a loader accepts a libc lacking GLIBC_2.39. No older-runtime compatibility,
actual symbol resolution, or alternative hard runtime floor is claimed.
The GLIBCXX_3.4.30 import is GLOBAL, and its version record also has flags zero.

The tests authenticate the complete target and compare the derived packet,
check the exact three named bindings, and exercise five corruption controls:
binding and name changes alter the join; an unknown version index is rejected;
a version-flag change alters the join; a target mutation fails authentication.
No mock target or invented model behavior is used. These are scoped proof of
static metadata, not target-equivalence tests or independent global validation.

## Results and limitations

This is a bounded additive observation, not a general ELF loader, a full import
inventory, a source reconstruction or a demonstrated deployment compatibility
fix. It does not edit existing executable code or progress/catalogue gates.
Original tooling and prose are independently authored; target-derived symbol
metadata does not relicense the captured binary or imported reference source.
No unlicensed inferred source is copied. No gate is requested.

Next question: can an explicitly authorized offline loader investigation qualify
the version requirement against particular runtime library identities? That is
outside this packet and has not been attempted. The required validation entrypoints and their local imports were inspected
before execution. The root package declares no lifecycle scripts; its pinned
182-package npm lock includes a Frida install hook, but this static packet does
not install or invoke npm/Frida/REA. Artifact downloads and question-ownership
network refresh are separate commands, not part of the required check paths.
No hosted CI result is established by this local audit or scoped run.
