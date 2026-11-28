# RE-002 · Which distributed linker can account for the node #115 stamp?

The [original provenance record](../RE-002-build-provenance/provenance-115.json) inferred a bundled Rust linker. The [build plan](../RE-002-node115-build-plan/README.md) located its stamp at file offset `0x64fce34`. This packet identifies a concrete candidate. The default stamp constructed from the official Rust 1.95.0 Linux x86-64 linker matches the complete node stamp, including the checkout directory. The same Rust release distributed for Apple Silicon emits a different repository string when linking an x86-64 Linux ELF.

- Task and component are RE-002 and `foundation`.
- Target is Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, GNU build ID `ac2880fcda5e49007a8e4fb1ea6aa7dd1b2eae01`.
- Status is a verified candidate for the final linker. The identity of the executable that linked the historical node, its flags and its build environment remain unresolved. This packet requests no completion gate or implementation-byte credit.

## Distribution evidence

The [official release manifest](https://static.rust-lang.org/dist/channel-rust-1.95.0.toml) pins the `pkg.rustc.target.x86_64-unknown-linux-gnu` xz component to SHA-256 `8426a3d170a5879f5682f5fbdd024a1779b3951e7baba685af2d6dc32a6dfc15`. The `rust-lld` member identified in [result.json](result.json) is 11,604,688 bytes and hashes to `60f305b55da767671e895b231e0c78e87f4ccbf790d7181842039c53bb60281c`.

Its allocated read-only `.rodata` contains the following distinct NUL-delimited strings. Offsets are relative to the start of the linker file.

| Linker file offset | Literal |
| --- | --- |
| `0x4f08f` | `Linker: ` (one trailing space) |
| `0x5424f` | `LLD 22.1.2 (/checkout/src/llvm-project/llvm 1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e)` |
| `0x46071` | `LLD_VERSION` |

At that LLVM revision the ELF linker constructs its default `.comment` from the prefix and its configured version string. Concatenating the first two literals gives the entire captured entry. The release and revision are identical across the two hosts tested here, while their configured repository strings differ. Rust packages the linker under the host-specific sysroot. [ELF comment generation](https://github.com/rust-lang/llvm-project/blob/1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e/lld/ELF/SyntheticSections.cpp#L68-L85) · [LLD version construction](https://github.com/rust-lang/llvm-project/blob/1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e/lld/Common/Version.cpp#L19-L35) · [Rust distribution layout](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/src/bootstrap/src/core/build_steps/dist.rs#L580-L590)

## Measured fixture links

The retained run used an `aarch64-apple-darwin` host and Apple clang 21.0.0. For every link the probe assembled [fixture.s](fixture.s) in a new directory as an x86-64 ELF relocatable. The object contains a six-byte read-only payload, zero executable bytes, and no input `.comment`. The GNU linker driver used `-shared --build-id=sha1`. The probe inspected the resulting ELF files without executing them.

| Fixture | Observed output comment | GNU build ID |
| --- | --- | --- |
| Rust 1.95.0, two fresh builds | LLD 22.1.2, Rust LLVM GitHub URL, revision `1cb4e383…` | `4b61996f3bb9ebdc9bf5e5ee2ddaf9684e2f0c9b` both times |
| Rust 1.95.0, one input byte changed at object file offset 68 | Same as both fresh builds | `2fcadb4d4b8da580cac1762a822eec81973e8753` |
| Rust 1.95.0, same object, upstream test override | `RE-002 link fixture control` | `bf8e53b7adfe49eb902e5d29ab4fed9c5c31efd0` |
| Rust 1.94.1, same object | LLD 21.1.8, Rust LLVM GitHub URL, revision `00d23d10…` | `09559dd879ed0b34c0aa383a39e84a136029dc02` |

Both fresh 1.95.0 ELF files have SHA-256 `61f3b468557fa1044d14a40bb239657eb8c8a28abe3d9d1710df76f6783c41e7`. The input change shows that different binaries can carry the same stamp. The override shows that the same linker can emit different stamps. The original node's build-ID algorithm and flags remain open. The Linux package finding above is static. The fixture measurements in this table were performed with macOS-hosted linkers. A native Linux run of the procedure below would test the distribution's full default stamp directly.

## Reproduce

Run from the repository root with a materialized node #115 LFS object and Python 3.11+. The default check reads the node, the fixture source and retained results.

```sh
packet=research/work-items/RE-002-node115-linker-stamp
python3 "$packet/probe.py"
```

Obtain the official Linux compiler component once. The probe checks the pinned archive hash before reading its single regular linker member. The static distribution check does not install or execute it.

```sh
archive=/tmp/rustc-1.95.0-x86_64-unknown-linux-gnu.tar.xz
curl -fL https://static.rust-lang.org/dist/2026-04-16/rustc-1.95.0-x86_64-unknown-linux-gnu.tar.xz -o "$archive"
python3 "$packet/probe.py" --archive "$archive"
```

For fixture replay, provision host-native Rust 1.95.0 and 1.94.1 with rustup and a Clang integrated assembler that accepts `--target=x86_64-unknown-linux-gnu`. The replay uses their bundled linkers and an otherwise empty linker environment with selected system paths. It writes temporary data-only ELF files, removes them on exit, and emits new JSON. On x86-64 GNU/Linux the 1.95.0 installed linker must match the authenticated distribution member and must emit the captured stamp. Full ELF hashes and build IDs are recorded separately for each host and assembler.

```sh
rustup toolchain install 1.95.0 1.94.1 --profile minimal
python3 "$packet/probe.py" --replay --archive "$archive" --output /tmp/re002-linker-replay.json
python3 -m unittest discover -s tests -p 'test_node115_linker_stamp.py'
```
