# RE-002: Which node94 imports account for the version maxima?

- Component: build provenance; no catalogue component or completion gate.
- Target: `artifacts/node/94/hl-node`, **91,774,280 bytes**, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Independent base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Claim status: observed ELF metadata; runtime/build-host interpretation unresolved.
- Included: the complete node94 dynamic version-requirement/import tables and
  attribution of the five existing namespace maxima. Excluded: node115, visor,
  code disassembly, call reachability, library loading and captured execution.
- No reference implementation source was used. Existing imports, pinned source
  commits, build-provenance records, catalogue and progress files are unchanged.

The maintained build-provenance report finds version-shaped strings in `.dynstr`.
This packet asks whether those maxima are actual ELF requirements and identifies
their providers and referencing imports. The answer agrees with the five saved
maxima; this is additional attribution, **not a corrected maximum or a discovered
compatibility defect**.

## Reproduce

From the repository root, with the existing authenticated LFS inputs available:
Use a fresh `--output` path; the producer refuses to overwrite an existing file.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/node94_version_requirements.py --output work/version-requirements-94.json
cmp work/version-requirements-94.json research/work-items/RE-002-version-requirements-94/observed.json
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_node94_version_requirements.py -v
make doctor verify test catalogue-check reproduce
sha256sum -c research/work-items/RE-002-version-requirements-94/MANIFEST.sha256
```

Python 3.12.14 and GNU readelf (Debian binutils) 2.44 were used on Linux x86-64.
`EXPORTS.json` retains the precise platform, commands, version output and raw
export hashes. The producer itself uses only Python's standard library and the
maintained `elf_index.sections` helper. GNU readelf is an independent static
cross-check, with explicit test skips when GNU readelf is unavailable. The
observed focused run has nine passes and no skips (`FOCUSED.json`). No compiler,
target process, emulator, loader, networking or chain action is invoked.

The producer reads the target once, authenticates the size and SHA-256 of that
same byte vector against `provenance/artifacts.json`, then parses it. Output is
written only after successful authentication and parsing. The raw readelf
exports read the unchanged retained target path; its full identity is checked
before and after those exports. Output consists of UTF-8 JSON with explicit LF;
the native exports are retained without normalization.

## Evidence

`observed.json` carries all source coordinates as integer **file offsets**, the
section linked VAs, original dynamic tags and all parsed version/import rows.
These are data-table records, not function boundaries or disassembled calls.

| Table | File interval, exclusive end | Entries |
| --- | --- | --- |
| `.dynsym` | `0x340..0x32f8` | 509, each 24 bytes |
| `.gnu.version` | `0x32f8..0x36f2` | 509, each 2 bytes |
| `.gnu.version_r` | `0x36f4..0x3ab4` | 7 provider headers, 53 auxiliary requirements |
| `.dynstr` | `0x3ad8..0x6bbd` | 12,517 bytes |
| `.dynamic` | `0x576bd70..0x576bf80` | 16-byte entries, terminated by `DT_NULL` |

The producer checks actual section types/links and agreement with `DT_SYMTAB`,
`DT_SYMENT`, `DT_STRTAB`, `DT_STRSZ`, `DT_VERSYM`, `DT_VERNEED` and
`DT_VERNEEDNUM`. It follows counted Verneed/Vernaux chains inside their section,
checks distinct indexes and ELF version-name hashes, and maps each undefined
dynamic symbol through its `.gnu.version` index. Providers must be named by
`DT_NEEDED`. All 53 requirement rows have referencing imports. Raw GNU exports
are in `raw/`; tests independently cross-check all 53 provider/name/index/flag
rows and all **497 versioned undefined symbols**.

The dynamic-symbol denominator is 509: 497 versioned undefined symbols, 10
unversioned undefined symbols, one defined symbol and the reserved null entry.
It is not a function census, called-import census or reconstruction percentage.

| Namespace maximum | Provider | Version index | Referencing undefined symbols |
| --- | --- | --- | --- |
| `GLIBC_2.39` | `libc.so.6` | 26 | 2: `pidfd_getpid`, `pidfd_spawnp` |
| `GLIBCXX_3.4.30` | `libstdc++.so.6` | 44 | 1: `_ZNSt18condition_variable4waitERSt11unique_lockISt5mutexE` |
| `CXXABI_1.3.11` | `libstdc++.so.6` | 42 | 3: `_ZnwmSt11align_val_t`, `_ZdlPvmSt11align_val_t`, `_ZdlPvSt11align_val_t` |
| `GCC_4.2.0` | `libgcc_s.so.1` | 31 | 1: `_Unwind_GetIPInfo` |
| `OPENSSL_3.0.0` | `libssl.so.3` | 6 | 30 |
| `OPENSSL_3.0.0` | `libcrypto.so.3` | 7 | 28 |

Equal namespace/version text can belong to distinct providers. Both OpenSSL
requirements and their separate 30/28 import lists are preserved. The maxima
therefore comprise five namespace values, six provider/version rows and 65
referencing undefined symbols. Full names and coordinates are in the JSON.

### Weak symbol binding is a separate field from version flags

The `GLIBC_2.39` Vernaux record at file offset `0x3a94` has `vna_other=26`
and `vna_flags=0`. Its version string begins at `0x6b9d`; provider `libc.so.6`
is identified by the Verneed header at `0x3744`.

| Symbol | Dynsym index / file offset | Versym file offset | Binding |
| --- | --- | --- | --- |
| `pidfd_getpid` | 173 / `0x1378` | `0x3452` | `STB_WEAK` (2) |
| `pidfd_spawnp` | 182 / `0x1450` | `0x3464` | `STB_WEAK` (2) |

Both version-symbol entries contain 26. The symbol binding comes from
`Elf64_Sym.st_info`, while the requirement flags come from `Elf64_Vernaux`.
In particular, the weak symbol binding does **not** set `VER_FLG_WEAK` (2) in
the observed requirement flags. This packet records the fields separately and
does not turn weak symbol binding into an optional-version or runtime-support
claim. All 53 observed requirement flags are zero.

## Implementation and comparison

`tools/node94_version_requirements.py` and its tests are independently authored
static tooling. There is no reconstructed Rust component, Cargo lockfile,
compiler-grid experiment, binary build, normalization mask or runtime comparator.
Exact binary metadata and raw readelf data support the statements above.

Nine tests cover authenticated target observations and counterfactual controls:

- reproduce the complete table counts, namespace maxima, duplicate-version
  provider split, original GLIBC import identities and source coordinates;
- independently cross-check all versioned imports and requirement/provider
  metadata with GNU readelf;
- change `vna_flags` on a copied byte vector and observe unchanged symbol
  bindings, then change one symbol binding and observe unchanged version flags;
- retarget one real Versym entry and one real provider-name offset and verify
  that attribution follows those fields;
- reject seven real table inconsistencies: wrong section link, dynamic pointer,
  out-of-section auxiliary record, incomplete provider/auxiliary chains, bad
  version-name hash and unresolved version index;
- reject a substituted target at the whole-input identity gate, and reproduce
  the committed JSON byte-for-byte;
- run the actual CLI on an existing sentinel output and preserve its bytes on
  failure, then generate the exact retained report at a fresh output path.

The structural and attribution counterfactuals run on altered in-memory copies
**below** the hash gate; a full-input digest failure cannot satisfy them. No
counterfactual is presented as a captured target or executed executable.

## Results and limitations

The actual five string-derived maxima are confirmed as version requirements,
with complete provider/import attribution for this digest. Exact header/table
facts, flags and bindings are observations. No inference of the original host,
minimum supported glibc, package image, historical linker flags or selected
runtime library is made. A declared requirement does not establish import-call
reachability, actual loader behavior, symbol availability or fallback behavior.

All existing component gates stay false. No node reconstruction, behavioral
equivalence or feature completion credit is requested. Node115 and visor are
separate targets and are outside this packet.

Next question: which call paths reference the two weak GLIBC 2.39 import slots,
and what static fallback conditions surround them? That requires instruction
and relocation evidence beyond these table facts; it remains open here.
