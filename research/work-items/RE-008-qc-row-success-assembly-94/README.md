# RE-008: conditional QC row-success assembly in node #94

- Component: consensus, RE-008. This is one bounded reader-copy projection,
  with no component gate or complete QC decoder claim.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline: upstream main
  `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Coordinates: linked ELF virtual addresses, half-open intervals. `freeze.json`
  has the original bytes and three asymmetric output predictions frozen before
  the Rust model. The later qualification that native helper output is
  stack-backed corrected the premise wording without changing these vectors
  or their five selected mutation sites.

## Bounded question and result

After raw20, both four-word helper calls, and the final byte read succeed,
which prior data bytes does the row callback place into its result? The scoped
straight-line corridor is `[0x4c7e546,0x4c7e5f7)`: 177 bytes, file offset
`0x4c7d546`, SHA-256
`c5bea9581a0c7b6f0a3386333ba73df42a8d89702d59b8ccd9236e59b56a1ef4`.
It belongs to complete owner FDE `[0x4c7e340,0x4c7e60d)`, 717 bytes,
FDE `0xf443ac`, CIE `0xce1518`, no LSDA, body SHA-256
`691aada3f78a0a84acaa2b4e75ce3c58fe68b1e852aa29a98e464287e1ebf512`.
GNU objdump 2.44 and LLVM objdump 19.1.7 match all 168 owner instruction
extents and raw bytes; the scoped corridor contains 38 instructions and no
branch/call/return.

Here O is the native row-result pointer in RBX. All offsets are byte offsets.
The three already successful helper results are *opaque bytes* in this claim:

| Prior result | Native staging and final stores | Corridor-owned O bytes |
| --- | --- | --- |
| raw20 | `0x4c7e362/36c` save its 16+4 bytes before later calls; `0x4c7e5da/5e5` copy them | `+0x08..+0x1b` (20) |
| first group | `0x4c7e39a..3b9` stage byte/7/qword/16 from the first `0x466bf60` result before the second reuses stack+0x28; `0x4c7e5c3/c6/d1/e8/ec` copy them | `+0x20..+0x3f` (32) |
| second group | `0x4c7e427..446` stage byte/7/qword/16; `0x4c7e56e/571/579/5f0/5f3` copy them | `+0x40..+0x5f` (32) |

The two seven-byte prefixes use overlapping DWORD stores. The later
`O+0x21` or `O+0x41` store overwrites the preceding `O+0x24` or
`O+0x44` store's **first** byte with the same source byte (the later store's
fourth byte). Thus each prefix is still contiguous. These
three ranges total **84 corridor-owned output bytes**. The corridor does not
write `O+0x1c..+0x1f`.

The 104-byte test view includes two separately credited completion writes:
the final byte at `O+0x60` is the prior one-byte field finding at
`0x4c7e5f7`, and the eight-byte success tag at `O+0..+7` is written after
`0x4c7e5fa/5fc` joins `0x4c7e4df`. Neither lies in the 177-byte corridor.
`O+0x61..+0x67` is also untouched on this path. The 11 untouched bytes are
preserved from a synthetic prefill in tests; they are not claimed initialized
by the native decoder.

## Entry and caller binding

The QC reader LEAs callback `0x4c7e340` at `0x4779fdb`, calls vector
reader `0x4589520` at `0x4779fea`, and that vector invokes its saved
callback at `0x45896a1`. Within the row owner, raw20 at `0x4c7e358`
must have its required success status, first group `0x4c7e395` must take
the zero-tag arm at `0x4c7e3c6`, and second group `0x4c7e422` must take
the zero-tag branch `0x4c7e450 -> 0x4c7e4f3` (raw `0f849d000000`).
The one-byte path must then pass its charge and nonempty guards and update
the cursor through `0x4c7e542`. Only then does this copy corridor run.

Actual helper outputs use a stack-backed slot at `[rsp+0x28]`, reused by the
two group calls. The first result's needed pieces are staged into other stack
locations and callee-saved registers before the second call. The Rust inputs
are immutable logical snapshots of those pieces. Ordinary register
preservation and valid live frame, decoder, input and output memory without
destructive external overlap are premises. The values, initialization and
failure behavior of the earlier helpers are **not** proved here.

The previous `RE-008-qc-recovery-byte-94` packet at commit
`6279dcfbd88655e08ed1632227f6840e1ade7a9e` owns the one-byte field,
its charge/EOF relation and the callback boundary. Open PR #1444 owns the
serializer's timeout/QC row field order; this packet binds the reverse
reader's *success copy* without re-claiming writer or primitive semantics.
The separate first-group failure work in another isolated lane is not
included. On 2026-11-01, upstream main was the pin above; a scan of all
156 open PR titles/bodies found no exact `0x4c7e546..0x4c7e5f7` site or
row-success assembly claim. Unpublished branches and later changes remain
outside that scan.

## Reproduce and negative controls

The static verifier reads the authenticated ELF, validates the selected
FDE/CIE and byte window, decodes the complete owner with both tools, and
requires every instruction byte to partition the body. It checks exact
caller/branch bytes. It writes one inert mode-0600 ELF copy under a temporary
directory, changes only one selected operand byte at a time, disassembles
each variant with both tools and restores the byte. Five site controls target
the second-group source staging, raw20 destination, first-group qword,
second-group first byte and second-group qword. The source/destination
predictions were manually fixed in `freeze.json` before the Rust model.
The Python projection and native mutants are **not** CPU execution or a proof
that arbitrary helper outputs are reachable.

```sh
python3 -B research/work-items/RE-008-qc-row-success-assembly-94/verify.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump \
  --out work/re008-qc-row-success-new
python3 -B research/work-items/RE-008-qc-row-success-assembly-94/verify_rust.py \
  --cargo /workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin/cargo \
  --rustc /workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin/rustc \
  --out work/re008-qc-row-success-rust-new
(cd research/work-items/RE-008-qc-row-success-assembly-94 && sha256sum -c MANIFEST.sha256)
```

The Rust projection is in the existing, real
`src/node94-consensus-admission` crate with its unchanged manifest,
lockfile and dependencies. Its function copies only the 84 corridor-owned
bytes into a caller-provided output buffer. The input-only example supplies
the success tag and final byte as separately credited context. Fresh locked,
offline debug and release builds under rustc 1.94.1 each matched all three
frozen 104-byte frames. Existing crate tests passed in both profiles:
36 unit plus 9 integration tests each; the example has no unit tests.
`observed/RESULTS.json` and `observed/RUST-RESULTS.json` preserve exact
static/control and build/output receipts. The Rust receipt retains all six
raw 104-byte outputs, argv, exit, stdout and stderr, the compiler/Cargo hashes,
all project source hashes, and Cargo dep-info closure over the exact `.rs`
files read by both example builds. No captured program was executed.

The first verifier draft incorrectly counted every crate example as a
compiler-read source even though Cargo builds only the selected example.
That would block combining this packet with the pending one-byte QC example
in #1509. The minimal correction pins all crate `src/*.rs`, the selected
`qc_row_success_input_only.rs`, `Cargo.toml` and `Cargo.lock`, then requires
Cargo dep-info to equal precisely the selected Rust source set. To test the
blocker, a temporary unrelated example containing `fn main() {}\n`
(SHA-256 `536e506bb90914c243a12b397b9a998f85ae2cbd9ba02dfd03a9e155ca5ca0f4`)
was added under `examples/`. Fresh debug/release builds still matched all
three frozen frames; that file appeared in neither project pins nor the
11 compiler-read `.rs` paths. `observed/EXTRA-EXAMPLE-RESULTS.json` retains
the raw build and output receipts. The temporary example was removed.
This is validation-source closure only; it does not change the target claim.

`make doctor` passed for static analysis. `make reproduce` passed: the
three captured inventories and refined literal classifications regenerated
from verified inputs. `make verify` authenticated all three captures and
signatures, then stopped in `verify_imports` with
`Modified source reference: references/can1357-hl`: this local source
worktree contains the authenticated 91,774,280-byte LFS payload at
`bin/hl-node-mainnet-new`, while HEAD has its matching 133-byte pointer,
and Git status reports that hydrated path modified. One retry with the
standard Git LFS clean/smudge/process filters supplied only through
`GIT_CONFIG_COUNT=3` exited at the same `verify_imports` check; no
configuration was persisted and no fetch occurred. `make catalogue-check`
reports a
stale generated `research/catalogue/components.json` on this pinned main,
and reproduces that failure in the untouched first-group-failure worktree
at the same commit. These are repository baseline/check-environment limits,
not a claim that all required checks passed. Full `make test` remains
pending coordinator integration.

This advances a complete QC decoder by fixing where its prior successful
field bytes go and which padding bytes remain unwritten. It does not establish
the group's scalar representation, charge/cursor composition, failed-group
paths, raw input validity, whole-row ABI/layout, vector allocation, source
message reachability, cryptographic validity or complete component behavior.
No progress gate changes. The next question is the second group's first
failure and its propagation to the row result under a proven first-group
success, including active error bytes and cursor/charge state.
