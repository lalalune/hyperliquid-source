# RE-002 · Ubuntu startup objects for the node #115 entry point

Ubuntu Noble's signed amd64 `libc6-dev` base package contains a compatible glibc startup routine. Its `_start` symbol spans the same 38 bytes as the node's previously established entry FDE. **29 of 38 bytes match in the unlinked object.** Both actual object relocations and one x86-64 linker relaxation account for the other nine bytes. Applying them at the previously mapped node destinations produces the complete captured 38-byte SHA-256. With Ubuntu Focal the symbol is 47 bytes and contains two additional startup references.

Target is Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Component is `foundation`, task RE-002. The [earlier entry packet](../RE-001-node115-entry-start/README.md) established the FDE, entry handoff and import. This comparison tests actual distributed startup objects as candidate inputs for a deterministic build.

## Six package objects, one node entry

| Ubuntu base package | Input | Symbol extent | Comparison with node |
| --- | --- | ---: | --- |
| Noble 2.39-0ubuntu8 | `Scrt1.o`, `rcrt1.o` | 38 B each | Identical complete object files, 29 raw and 38 relocation-qualified bytes |
| Noble 2.39-0ubuntu8 | `crt1.o` | 38 B | Different complete file, same entry body and two entry relocations |
| Focal 2.31-0ubuntu9 | `Scrt1.o`, `rcrt1.o`, `crt1.o` | 47 B each | Different extent, four entry relocations including `__libc_csu_fini` and `__libc_csu_init` |

The node entry VA is `0x1419300`, file offset `0x1418300`. Its complete FDE ends at `0x1419326` (exclusive). Noble's relocatable symbol starts at `.text+0`, file offset `0x90`. The source `Scrt1.o` hashes to `9438d15c4bac893a0e3aad2c2c86ccbceb59d5872bd07101949f237ee1c92a8b`. The public assembly describes a GOT reference to `main` and a GOT-indirect call through `__libc_start_main`. [glibc 2.39 startup source](https://github.com/bminor/glibc/blob/glibc-2.39/sysdeps/x86_64/start.S#L98-L119)

| Offset from entry | Object relocation | Verified destination and link operation |
| --- | --- | --- |
| `0x1b` | `R_X86_64_REX_GOTPCRELX main - 4` | Node main shim at `0x2cef8f0`. The load opcode at entry + `0x19` relaxes from MOV to LEA. Signed displacement is `0x18d65d1`. |
| `0x21` | `R_X86_64_GOTPCRELX __libc_start_main - 4` | Node GOT slot at `0x64df458`, bound by `R_X86_64_GLOB_DAT`. The indirect call remains intact. Signed displacement is `0x50c6133`. |

The replay writes each signed displacement as destination + addend − address of the relocation field. The captured entry hash is `cf432d50b96a11a67b03f671fe51599dd44a6b9c5a009eefba514c487d9e23bd`. No bytes are masked. The record includes all relocations of each package object, including its separate `.eh_frame` entries. All six objects and the node share the full 32-byte GNU Linux 3.2.0 ABI note. That note cannot distinguish the two releases. [Object identities, symbol sizes and relocation records](result.json) · [Independently mapped node import](../RE-001-node115-entry-start/selected-relocations.txt)

## Independent real linker check

Two additional x86-64 Linux PIE fixtures link the authenticated Noble `Scrt1.o`, the matching signed `libc6` package's real `libc.so.6`, and an independently authored three-byte [fixture main](main.s). Neither executable runs. The linker chooses its own addresses. The recorded host is Apple Silicon, using Apple clang 21.0.0 and Rust 1.95.0's bundled LLD 22.1.2.

| Link | Main reference in linked entry | Libc reference |
| --- | --- | --- |
| Default relaxation | Direct LEA to the fixture's independently located `main` symbol | `R_X86_64_GLOB_DAT` for `__libc_start_main@GLIBC_2.34` |
| `--no-relax` | MOV via a separate GOT slot with `R_X86_64_RELATIVE` to `main` | Same versioned symbol and binding |

The complete linked entry equals the independently replayed object in both cases. Only the default case exhibits the node's direct-main instruction form. The fixture's addresses, whole-ELF and extent hashes, library SHA-256, linker identity and package signatures are in [fixture-result.json](fixture-result.json).

## Reproduce

Run from this directory with the repository's materialized node #115 LFS artifact, Python 3.9+, `gpgv`, `ar`, and `zstd`. Use the trusted [Ubuntu archive keyring](https://packages.ubuntu.com/noble/ubuntu-keyring) containing the 2012 and 2018 keys. The required 2018 signing fingerprint is `F6ECB3762474EDA9D21B7022871920D1991BC93C`. Focal also carries the signature of `790BC7277767219C42C86F933B4FE6ACC0B21F32`. The first run acquires and verifies pinned signed releases, compressed amd64 package indexes, and named packages. Later runs use the cache offline. [Focal signed index root](https://archive.ubuntu.com/ubuntu/dists/focal/InRelease) · [Noble signed index root](https://archive.ubuntu.com/ubuntu/dists/noble/InRelease)

```sh
cache=$(mktemp -d)
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
python3 verify.py "$cache" --keyring "$keyring" --fetch
python3 verify.py "$cache" --keyring "$keyring"
```

For the link experiment, install Rust 1.95.0 with rustup, a Clang assembler targeting x86-64 Linux, and GNU readelf. Each run writes two temporary PIEs, verifies both, then removes them. The JSON records host-specific identities. On the recorded toolchain a second run reproduced the entire result.

```sh
rustup toolchain install 1.95.0 --profile minimal
python3 link_fixture.py "$cache" --keyring "$keyring" --fetch --output /tmp/re002-startup-link.json
python3 link_fixture.py "$cache" --keyring "$keyring" --output /tmp/re002-startup-repeat.json
cmp /tmp/re002-startup-link.json /tmp/re002-startup-repeat.json
```

The evidence qualifies a published startup implementation. It cannot identify the exact original package revision or object filename. The three Noble candidates supply indistinguishable entry extents. Rebuilding glibc from source and identifying the remaining linker inputs are open questions. No component gate, byte-registry change or first-party implementation credit is requested.
