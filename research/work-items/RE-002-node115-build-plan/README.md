# RE-002: node #115 deterministic Linux build plan

- Component ID: `foundation` (bounded build-provenance question, not component ownership).
- Target release and full SHA-256: node #115, Linux x86-64, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `a8616af9432b8d8517b2af677880e117b7c28ef3`
  (workspace base; the working tree used for this analysis was verified against the
  live `main` at this sha). No reference-source code is used or copied.
- Claim status: observation for the fields marked `exact`; inference for the
  fields marked `inferred`; unresolved for the fields marked `unresolved`.
- Scope included and excluded: included are the build inputs that the shipped
  node bytes record or bound. Excluded are runtime execution, any rebuild, the
  original build configuration, and every first-party code body.

`docs/TASKS.md` row RE-002 asks to "Document exact vs inferred compiler flags,
crate graph and fork versions; deterministic Linux build plan with unresolved
fields". The merged `RE-002-build-provenance` record answers the first part. The
plan is the part that is still missing: `docs/TOOLCHAINS.md` calls the matched
image "recorded requirements for a later matched build image" and warns that
matching the Rust release alone is not enough for byte identity.

This packet states that plan. It separates three things that are easy to mix:

1. build inputs the bytes prove (`exact`),
2. inputs that a stated reading of the bytes supports (`inferred`),
3. inputs no reading of the bytes can settle (`unresolved`).

It does not restate the existing provenance record. It re-derives the exact rows
from the artifact with its own reader and records agreement with the earlier
record where both describe the same bytes. It performs no rebuild, so it makes no
claim about byte identity. The independent compiler experiment below builds only its own fixture.

New analysis code and documentation use the repository's MIT terms. The captured
node retains its upstream rights. No source is copied or inferred from a rebuild.

## Reproduce

Run from the repository root:

```bash
python3 research/work-items/RE-002-node115-build-plan/verify.py
python3 research/work-items/RE-002-node115-build-plan/verify.py --control
```

- Tool: `python3 --version` = 3.12.3. No package outside the standard library is
  imported, and no external disassembler, linker or container runs.
- Input: `artifacts/node/115/hl-node`, SHA-256 above, 105,896,032 bytes.
- Working directory: the repository root. The script resolves the artifact from
  its own location, so any working directory inside the repository works.
- Platform: Linux x86-64. The script maps the file read-only and needs no write
  access to the artifact.
- Declared side effects: none. The script reads the file, prints one row per
  derived field, and exits 0 when every `exact` row matches. `--control` copies
  the file into memory, flips one byte of `.comment`, and must exit non-zero.
- Output hashes: the plan text is `build-plan.json` in this directory, already in
  the packet manifest. The artifact digest is printed by every run and checked
  against the digest in the plan.

Observed result at the recorded digest:

```text
plan matches the artifact
control: one byte of .comment flipped
control result: FAILED AS REQUIRED
```

## Evidence

Every row below is a file offset in the shipped artifact. The coordinate system
is the file, not a virtual address, because the sections used here are not
executable and carry no load address of their own.

| Observation | Section | First file offset | Count |
| --- | --- | ---: | ---: |
| `rustc version 1.95.0 (59807616e 2026-04-14)` | `.comment` | `0x64fce08` | 1 |
| `Linker: LLD 22.1.2 (/checkout/src/llvm-project/llvm 1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e)` | `.comment` | `0x64fce34` | 1 |
| `GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0` | `.comment` | `0x64fce93` | 1 |
| `clang version 22.1.0-rc2` | `.comment` | `0x64fcec0` | 1 |
| `/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860` | `.rodata` | `0x430444` | 110 |
| `/home/ubuntu/hl/code_Mainnet` | `.rodata` | `0x430405` | 863 |
| `z_vendor` | `.rodata` | `0x430422` | 4 or more |
| `z_forks` | `.rodata` | `0x4305e9` | 1 or more |
| `5.3.0-1-ge13ca993e8ccb9ba9847cc330696e02839f328f7` | `.rodata` | `0x95e058` | 1 |

Section coordinates used by the reader, with size and file offset:

| Section | File offset | Size | Address |
| --- | ---: | ---: | ---: |
| `.interp` | `0x2e0` | 28 | `0x2e0` |
| `.dynstr` | `0x3af0` | 12,533 | `0x3af0` |
| `.gcc_except_table` | `0x16c2c0` | 2,900,276 | `0x16c2c0` |
| `.rodata` | `0x430400` | 7,792,192 | `0x430400` |
| `.dynamic` | `0x64dd248` | 528 | `0x64df248` |
| `.comment` | `0x64fce08` | 209 | not loaded |
| `.eh_frame` | `0xca6ed8` | 7,803,772 | `0xca6ed8` |

The counts for `z_vendor` and `z_forks` are lower bounds in this table: the
reader stops after the first hits to stay bounded. The plan does not depend on
those counts, only on the strings being present.

Agreement with the earlier record. `RE-002-build-provenance/provenance-115.json`
was derived by another tool. For every byte fact this packet also derives, the two
records agree: the four `.comment` stamps at the same offsets, the rustc commit
path, the source root, the jemalloc version string, `DT_NEEDED`, `DT_FLAGS` and
`DT_FLAGS_1`, the `GLIBC`/`GLIBCXX`/`CXXABI`/`OPENSSL` maxima, the hardening
imports, the `.gcc_except_table` size, and the absence of `.symtab` and `.debug*`.
Two independent readings of the same file reaching the same numbers is the
useful part; this packet adds no second claim about them.

Boundaries validated: the ELF header, the section table and every section used
were read through the section headers, and every scan is limited to one section
by its own offset and size. The reader also requires the artifact digest and size
to equal the values in the plan, so a different artifact fails closed instead of
producing a plausible-looking table.

Limits of this analysis: it is complete for the rows it derives. It reads no
instruction, no unwind record and no symbol, so it cannot rank functions or
attribute them to a crate. Nothing here is timed out or range-limited.

## Implementation and comparison

Not yet implemented and not yet measured. There is no independent Rust path, no
`Cargo.lock`, no two-build comparison and no normalized comparison in this
packet, and none is implied. A rebuild is what would turn the plan into a matched
image, and `docs/TOOLCHAINS.md` already records why matching the Rust release
alone cannot achieve byte identity.

Corruption control: `verify.py --control` flips one byte inside the first
`.comment` stamp. The check must fail, and it reports the exact field it caught.
A checker that passes a corrupted input would prove nothing.

Fixture identity: the plan is bound to one digest. Rows are not transferable to
the visor capture or to any other release.

## Results and limitations

Machine-readable result: `build-plan.json` holds one row per field, and every row
marked `exact` carries the key that `verify.py` re-derives. The plan has 33 rows:
17 `exact`, 6 `inferred` and 10 `unresolved`.

What passed: all 17 exact rows match the artifact, at the digest in the plan, and
the corruption control is detected.

What remains unknown, and why the bytes cannot settle it:

| Field | What would resolve it |
| --- | --- |
| `opt_level` | instruction patterns of a rebuilt known function at each opt-level |
| `codegen_units` | function ordering and partitioning in a matched rebuild |
| `lto` | cross-crate inlining evidence against a matched rebuild |
| `RUSTFLAGS` | the original build configuration; it is not embedded |
| `target.cpu_features` | itemised unconditional AVX/BMI use outside dispatched paths |
| `overflow_checks` | per-crate compiler invocations or equivalent records covering profile overrides |
| `frame_pointers` | a prologue survey, kept separate from the CFA census |
| vendored crate versions | vendor directory names that carry a version, or the original vendor plan |
| first-party crate versions | the original workspace; first-party paths carry no version |
| `Cargo.lock` | not embedded; only the original build record or a matched rebuild |

### What a checked increment establishes

The [RE-001 caller record](../RE-001-node115-loc-edge-1563f76/record.json)
already identifies the taken edge at node VA `0x1563e9b`, the source location
`base/src/u.rs:163:17`, and the relocated callee at `0x1681da0`. On the
fallthrough the caller increments the loaded 64-bit word and stores it back.
At the all-ones boundary the taken path passes the location to a helper that
loads the literal `attempt to add with overflow`. This establishes a checked
operation at the site. The original Rust expression and the flags used for
other compiler invocations remain unknown.

Reproduce the additional instruction and literal reads with LLVM objdump
from the repository root (link-time ELF virtual addresses):

```sh
target=artifacts/node/115/hl-node
llvm-objdump -d --start-address=0x1563e93 --stop-address=0x1563ea8 "$target"
llvm-objdump -d --start-address=0x1681da0 --stop-address=0x1681db9 "$target"
# .rodata starts at both VA and file offset 0x430400 on this target.
od -An -tc -j "$((0x46eadd))" -N28 "$target"
python3 research/work-items/RE-002-node115-build-plan/profile_control.py
```

The first read shows a comparison against `-1`, a jump to `0x1563f76`
on equality, and `incq %rdx` followed by a store on fallthrough. The helper's
RIP-relative load at `0x1681da7` addresses `0x46eadd` (next IP
`0x1681dae` plus signed displacement `-0x12132d1`), the start of the literal.

The control builds one library with checks enabled and links that exact library
into two executables. The root and library compile the same ordinary Rust
addition. Only the root's overflow setting changes. With rustc 1.95.0
(`59807616e`) on aarch64 macOS, both additions returned `u64::MAX` for
`u64::MAX - 1`. For `u64::MAX` the library panicked in both executables;
the root panicked with checks enabled and returned zero with checks disabled.
Thus even an observed first-party checked addition is consistent with both
root settings. This compiler-behavior control uses host-built fixture code.
It makes no assumption about crate boundaries in the captured node.

Requested progress gate: none. This packet does not cover the whole scope of any
component gate. It covers one task row's remaining deliverable, and a gate stays
false until its own entire scope is covered with an evidence path.

A known limit: the `.comment` stamps identify the compiler and linker, but the
plan cannot say whether the toolchain was invoked through Cargo or through a
script, so the flag set stays untested. The plan therefore states what a matched
image must set, not that any image has matched.

Next question: for one bounded function that this release's provenance record
already binds, does a rebuild at the plan's settings reproduce its bytes, and
which of the ten unresolved inputs changes the result first?
