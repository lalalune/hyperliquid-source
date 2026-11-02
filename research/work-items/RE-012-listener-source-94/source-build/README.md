# Licensed source-build candidate for the node94 listener leaf

One complete selected function was compared: target ELF VA
`[0x3cd6690,0x3cd67c1)`,305 bytes/81 instructions, against the actual public
Mio1.0.2 `TcpListener::bind` symbol,364 bytes/94 instructions. The result is
**0/1 raw-equal,0/1 relocation-only equal,1/1 unmatched**. This is useful negative
build evidence, not byte equivalence or proof of a unique historical source
version. The original dependency graph, feature resolution, code-generation
options and application integration remain unknown.

The target has seven calls through six named import slots. The candidate has
nine actual `R_X86_64_GOTPCREL` call relocations because the compiler duplicated
`socket` and `setsockopt` into separate valid IPv4/IPv6 branches. The target
caches its discriminant and shares those calls. The complete operations, literal
arguments, error representation and cleanup structure correspond to the public
source, but code layout and instruction selection differ. No optimization-flag
search, target-byte transplantation or handwritten replacement was attempted.
Invalid enum representations are outside the public Rust `SocketAddr` domain;
this candidate does not claim all arbitrary target pointer bytes are safe Rust
inputs.

## Exact public inputs

The following official archives were downloaded, hashed and retained in the
ignored acquisition directory. Crate checksums were checked against exact
version records from the crates.io sparse registry. The Rust archive matches
both its official HTTPS SHA-256 sidecar and the prior RE-002 archive identity;
this build does not add a detached-signature verification claim.

| Input | SHA-256 | Source |
| --- | --- | --- |
| `mio-1.0.2.crate` | `80e04d1dcff3aae0704555fe5fee3bcfaf3d1fdf8a7e521d5b9d2b42acb52cec` | [published crate](https://static.crates.io/crates/mio/mio-1.0.2.crate) |
| `libc-0.2.149.crate` | `a08173bc88b7955d1b3145aa561539096c421ac8debde8cbc3612ec635fee29b` | [published crate](https://static.crates.io/crates/libc/libc-0.2.149.crate) |
| `rust-std-1.94.1-x86_64-unknown-linux-gnu.tar.xz` | `74109ee2c19098f1d7122087dd338a8f643203b3ce678c9d58169db733e17a03` | [official distribution](https://static.rust-lang.org/dist/rust-std-1.94.1-x86_64-unknown-linux-gnu.tar.xz) |

Mio's embedded package VCS metadata names commit
`e66deb9aa253d0763d1f58e17767700a9cc5fa2d`; libc's names
`d80e8bd3056d82fec80c022819084bdb0be3bdaa`. These are package provenance fields,
not a recovered node lockfile. The exact Mio manifest and five previously
retrieved source/license files were byte-compared with the published crate;
`prior-source-check.json` preserves the matches. The selected version records,
source tree hash manifest and candidate dependency choices are retained.

The target contains a `mio-1.0.2/src/event/events.rs` path. That supports the
presence of that package label somewhere in the binary, not unique attribution
of this leaf. The comparison itself rejects exact byte identity under the
declared build. Neighboring Mio versions can share these source functions; no
unique version claim follows from a matching public-source protocol.

## Offline build recipe

`build.py` takes three pinned archives and a native Rust1.94.1 compiler. It
requires compiler commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, extracts the
official Linux standard library into a private build sysroot, and compiles the
unmodified published crates directly. No system rustup state, repository pin or
source file is changed. No Cargo resolver or invented original Cargo.lock is
used. The candidate graph is Mio1.0.2 with features `net,os-poll`, default `log`
disabled, and libc0.2.149 with `default,std`. The libc version is the manifest's
minimum compatible version, selected for a bounded candidate only.

Code-generation options are fixed: Linux x86-64 GNU baseline, opt3, one codegen
unit for complete object extraction, unwind panic strategy, no debug assertions,
overflow checks or debuginfo, and an explicit path remapping. They are candidate
settings, not recovered target settings. No listener executable is linked or run.

Mio has no build hook. The complete manifests and libc `build.rs` were reviewed
before compilation. Only the reviewed libc host configuration helper executes:
it queries the explicit Rust compiler version and emits cfgs. Its PATH is empty,
so optional `freebsd-version` and `emcc` probes cannot resolve. Official archive
install scripts are never executed. These helper processes are distinguished
from captured code and listener execution, which did not occur.

The initial direct rustc attempt hit Mio's published `deny(dead_code)` on private
`SourceFd` under this feature set and current compiler. That failed attempt is
retained. Adding `--cap-lints allow`, the dependency lint policy, was the only
change required to compile. Source, features and optimization settings remained
unchanged. This warning policy does not mask any byte difference.

Example, from a directory containing these exported scripts:

```sh
python3 -O -B build.py \
  --input-dir /path/to/pinned-archives \
  --out /path/to/fresh-build \
  --rustc /path/to/rust-1.94.1/bin/rustc
python3 -O -B compare.py \
  --target /path/to/authenticated/node94/hl-node \
  --object /path/to/fresh-build/candidate-release/mio.o \
  --out /path/to/fresh-comparison
python3 -O -B verify_export.py
```

Python3.14 and Capstone5.0.7 were used; `build.py` uses only the Python standard
library. All output directories must be fresh. The recipe has been replayed
offline. Both Linux rlibs and the full `mio.o` are byte-identical across the
original and portable runs. The small host build-configuration helper differs
because its input path is not remapped; it is not the Linux listener artifact
and is not exported. Selected body bytes and comparison records repeat exactly.

## Comparison and evidence limits

`comparison.json` binds the complete target digest, unique actual FDE/CIE,
selected symbol/section metadata, full body hashes, actual object relocations,
and named target GOT-slot GLOB_DAT writers. All80,300 target RELA records and
121,299 FDEs were parsed. The selected source body is taken from its actual
symbol extent in the complete object, not from a transplanted byte window.

Only actual four-byte external GOT displacement fields are normalized:
28 target bytes and36 candidate bytes. Import identities and offsets must also
match. No opcode, immediate, internal branch, register, stack offset or inserted
instruction is masked. Since the complete lengths differ, both whole-window
comparisons fail. Five comparer controls check identical input, a real relocation
field change, a nonrelocation byte change, a wrong import identity and truncation.
`verify_export.py` replays the selected-export consistency checks; authenticating
external provenance requires `compare.py` on the full target and rebuilt object.

The selected raw body files, relocation records, GNU listings, actual build
commands, source provenance, and failed/successful logs are retained here.
Local paths in published command/log text are replaced only by documented
`<build>`, `<portable-build>`, `<inputs>` and `<rustc>` tokens; original raw logs
remain in ignored work with their exact byte counts and hashes in
`log-normalization.json`. No whole object or host executable is published.

No native listener/syscall execution, captured execution, instruction emulation,
protocol-vector replay, original crate graph, unique source version, whole-node
equivalence or component completion is claimed. Parent-owned protocol-vector
research and broader repository checks are separate evidence.

## Rights

Mio source copies under `source-evidence/mio-1.0.2/` retain their MIT copyright
and `MIO-LICENSE-MIT`. libc copies retain `LIBC-LICENSE-MIT`, elected from their
MIT OR Apache-2.0 license. Rust distribution provenance retains
`RUST-LICENSE-MIT`. Captured target bytes keep the repository's existing artifact
rights and provenance; these source licenses do not relabel the captured node.
New scripts and analysis were authored by 신준 under the project MIT license.
