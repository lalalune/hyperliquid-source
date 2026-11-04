# RE-002: node #115 dynamic symbol-version requirements and one bounded libstdc++ PLT window

- Component ID: RE-002 build provenance - dependency identity for `libstdc++.so.6` and `libc.so.6`.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Claim status: observation from the pinned bytes; the single inference is labelled as such.
- No target execution, no target copy, no network, no signing, no key material, no component gate.

## Question

Which dynamic symbol-version requirements does node #115 declare against
`libstdc++.so.6` and `libc.so.6` - the `DT_VERNEED` record set reached through
`.dynamic` -> `.gnu.version_r` -> `.gnu.version` -> `.dynsym` - and what do the
bytes of one bounded, relocation-bound `libstdc++.so.6` PLT window contain?

## Scope

Included: ELF section geometry for `.dynsym`, `.dynstr`, `.dynamic`,
`.gnu.version`, `.gnu.version_r` and `.text`; the `DT_NEEDED` order; the
`DT_VERNEED`, `DT_VERNEEDNUM` and `DT_VERSYM` entries; every version-need
record and version string in chain order; the dynamic-symbol version-index
census; and one 16-byte `.plt` entry with its `.rela.plt` binding.

Excluded: no source build, no statement about which runtime library version is
actually loaded, no execution or emulation, no whole dependency graph, no wire
or protocol claim, no component gate. The recorded window is an indirect-jump
stub belonging to the `libstdc++.so.6` dependency. Per CONTRIBUTING.md such a
shared dependency window counts only in target totals and the dependency
table, never as reconstructed first-party node bytes, and this packet claims no
reconstructed or equal bytes.

## Derived observations

Section geometry (VA / file offset / size):

| Section | addr | offset | size |
| --- | --- | --- | --- |
| `.dynsym` | `0x340` | `0x340` | `0x2fd0` |
| `.dynstr` | `0x3af0` | `0x3af0` | `0x30f5` |
| `.dynamic` | `0x64df248` | `0x64dd248` | `0x210` |
| `.gnu.version` | `0x3310` | `0x3310` | `0x3fc` |
| `.gnu.version_r` | `0x370c` | `0x370c` | `0x3c0` |
| `.text` | `0x1419300` | `0x1418300` | `0x4fd7700` |

`DT_NEEDED` order: `libstdc++.so.6`, `libssl.so.3`, `libcrypto.so.3`,
`libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, `ld-linux-x86-64.so.2`.

`DT_VERNEED` `0x370c`, `DT_VERNEEDNUM` 7, `DT_VERSYM` `0x3310`:
7 version-need records carrying 53 version indices.

Dynamic-symbol census: 510 dynamic symbols, 510 version indices, 498 symbols
carry a version-need index, and 0 defined non-empty versioned symbols.
Observation: every versioned dynamic symbol in this capture is an undefined
import, so the declared version identity attaches to imported C and C++
runtime symbols and not to first-party exports. No defined `.text` symbol
carries a `GLIBCXX_` or `CXXABI_` index.

Version-need records, in `.gnu.version_r` chain order (file, revision, entries):

| file | revision | entries |
| --- | ---: | ---: |
| `libstdc++.so.6` | 1 | 20 |
| `libssl.so.3` | 1 | 1 |
| `libcrypto.so.3` | 1 | 1 |
| `libgcc_s.so.1` | 1 | 3 |
| `libm.so.6` | 1 | 2 |
| `libc.so.6` | 1 | 25 |
| `ld-linux-x86-64.so.2` | 1 | 1 |

`libstdc++.so.6` entries in chain order:
35 `GLIBCXX_3.4`, 47 `GLIBCXX_3.4.9`, 41 `GLIBCXX_3.4.11`, 40 `GLIBCXX_3.4.14`,
45 `GLIBCXX_3.4.15`, 50 `GLIBCXX_3.4.17`, 39 `GLIBCXX_3.4.18`, 48 `GLIBCXX_3.4.19`,
43 `GLIBCXX_3.4.20`, 33 `GLIBCXX_3.4.21`, 49 `GLIBCXX_3.4.22`, 46 `GLIBCXX_3.4.26`,
37 `GLIBCXX_3.4.29`, 44 `GLIBCXX_3.4.30`, 34 `CXXABI_1.3`, 38 `CXXABI_1.3.5`,
52 `CXXABI_1.3.7`, 36 `CXXABI_1.3.8`, 32 `CXXABI_1.3.9`, 42 `CXXABI_1.3.11`.

Other records: `libssl.so.3` 6 `OPENSSL_3.0.0`; `libcrypto.so.3` 7
`OPENSSL_3.0.0`; `libgcc_s.so.1` 4 `GCC_3.0`, 19 `GCC_3.3`, 31 `GCC_4.2.0`;
`libm.so.6` 53 `GLIBC_2.2.5`, 8 `GLIBC_2.29`; `ld-linux-x86-64.so.2` 13
`GLIBC_2.3`; `libc.so.6` 3 `GLIBC_2.2.5`, 24 `GLIBC_2.3`, 10 `GLIBC_2.3.2`,
12 `GLIBC_2.3.4`, 18 `GLIBC_2.4`, 28 `GLIBC_2.5`, 54 `GLIBC_2.6`, 14
`GLIBC_2.7`, 15 `GLIBC_2.9`, 16 `GLIBC_2.10`, 5 `GLIBC_2.14`, 22 `GLIBC_2.15`,
30 `GLIBC_2.16`, 9 `GLIBC_2.17`, 27 `GLIBC_2.18`, 26 `GLIBC_2.25`, 29
`GLIBC_2.27`, 25 `GLIBC_2.28`, 21 `GLIBC_2.29`, 17 `GLIBC_2.30`, 23
`GLIBC_2.32`, 11 `GLIBC_2.33`, 2 `GLIBC_2.34`, 51 `GLIBC_2.38`, 20
`GLIBC_2.39`. The full record text is in `version-needs.txt`.

Inference (labelled): the `GLIBC_2.34` and `GLIBC_2.38`/`GLIBC_2.39`
requirements are consistent with a modern glibc build host, but the bytes do
not name the build distribution and this packet does not claim one.

## Window

One `.plt` entry bound by `.rela.plt` to a versioned `libstdc++.so.6` import:

| field | value |
| --- | --- |
| kind | `plt-thunk` |
| section | `.plt` |
| addr | `0x63f0d80` |
| file offset | `0x63efd80` |
| size | 16 bytes |
| instruction | `ff 25 8a d5 0f 00` - `jmp QWORD PTR [rip+0xfd58a]` to slot `0x64ee310` |
| relocation | `.rela.plt` |
| symbol | `_ZdlPvm` |
| version | `CXXABI_1.3.9` |
| library | `libstdc++.so.6` |
| body sha256 | `1600e1cb5479b4da18c28654fb07a433caeb4671da6ed2d04e73f435ca915c9e` |
| body hex | `ff258ad50f006834000000e9a0fcffff` |

The same bytes are recorded in `window.bytes.txt`, `evidence.json` under
`window`, and re-derived by the packet verifier from the pinned capture. The
jump displacement resolves to the recorded slot address; the entry is a
dependency stub, so no first-party semantics are inferred from it beyond the
relocation binding.

## Reproduce

From the repository root, with the pinned capture materialized and GNU binutils
available:

```sh
python3 -B tools/foundation_libstdcxx_abi.py --format text
python3 -B tools/foundation_libstdcxx_abi.py --packet research/work-items/RE-002-node115-libstdcxx-abi
make doctor verify test catalogue-check
```

The tool reads `artifacts/node/115/hl-node` in place, authenticates the digest
before parsing, re-derives every recorded value and rejects any packet value
that differs from the bytes; it also runs in-memory corruption controls on a
private copy (truncation, broken magic, zero `DT_VERNEED`, zero
`DT_VERNEEDNUM`, shortened `.gnu.version`, shortened `.dynsym`, altered
needed-file name, altered version name) that must be rejected or must change
the named derived field. The focused packet verifier at
`test-results/slop-workbench/packet-33b51122bfdc.py` performs the same
independent derivation plus the window selection and manifest check, and fails
with an assertion while any packet file is absent or any recorded value
differs; its recorded output is the retained proof for this packet.

## Results and limitations

Recorded here: what the pinned bytes declare and require from their external C
and C++ runtime libraries, plus one relocation-bound dependency stub.

Not verified or claimed: no source build, no link against a particular
`libstdc++`/`libc` version, no statement about symbols resolved at run time, no
complete dependency graph, no first-party semantics of any import, no
byte-equality or reconstruction credit, and no progress gate. This packet is
dependency identity only; it is intentionally not counted as reconstructed
first-party component bytes.

Next question: bind one first-party `.text` call site to a specific versioned
`libstdc++` import through this same relocation chain, so the dependency
requirement is tied to observed node code rather than to the import table alone.
