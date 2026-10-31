# Licensed source inputs

These are exact upstream Zstandard source/header/license bytes from the official
`meta/zstd` repository (formerly `facebook/zstd`). `UPSTREAM.json` in the parent
packet records immutable commits, Git blob identities, lengths and SHA-256s.

| Source directory | Official release tag | Immutable commit |
| --- | --- | --- |
| `zstd-1.5.6` | `v1.5.6` | `794ea1b0afca0f020f4e57b6732332231fb23c70` |
| `zstd-1.5.7` | `v1.5.7` | `f8745da6ff1ad1e7bab384bd1f9d742439278e99` |

Each assembly/header preamble expressly permits selecting the BSD-style
`LICENSE` or GPLv2 `COPYING` terms. This packet selects the BSD license and
retains the complete original Meta copyright notice, conditions and disclaimer
in each version's LICENSE. These third-party inputs are not relabeled MIT.
No endorsement or original Hyperliquid dependency/version identity is claimed.

The generated tiny ET_REL objects and raw code exports in the parent evidence
directory are research build artifacts from the licensed 1.5.6 inputs. They
carry the same upstream rights/notices; they are not captured binaries, Rust
implementations or a reconstructed node. Installed GCC/glibc headers remain
external toolchain dependencies with their own recorded terms; their source
is not vendored here.
