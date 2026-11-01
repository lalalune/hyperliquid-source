# RE-014 follow-on: node #115 PadAdapter callback trace

Status: bounded static comparison, no source or original-build identity claim.
Initial packet base: `3324e50333042b391312515e542279ca21f63dc8`; carried
forward to `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. This answers the
helper-semantic question left open by
[`RE-014-node115-field-adapter-drift`](../RE-014-node115-field-adapter-drift/README.md).
That packet's official libcore correspondence is context, not a transferred
proof. The comparison below is from the two captured node bodies themselves.

| Target | Full file admission | Selected FDE extent | Complete body SHA-256 |
| --- | --- | --- | --- |
| node #94 | 91,774,280B; `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` | `0x157d000..0x157d26e`, 622B | `d62080d0724a750e0162d6a0563c7a056ae76e2212fd48310f89bcf8809dfde4` |
| node #115 | 105,896,032B; `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` | `0x1686bd0..0x1686e46`, 630B | `fc968173616031f08d0a0e77dedca4e6cc4b81ddd1f7cb57e74b10cfae20cb2d` |

The selected `.eh_frame_hdr` lookups bind each complete body to its FDE.
#94's FDE SHA-256 is
`6821bd0ad7216691943a9354bf9e2c5cd611a5b33c7c6c2bd32468dc03d29572`;
#115's is
`88e77a816ef71b7b5015412fb127114c3680f8f2e267df82099547db1c375529`.
Both selected CIE bytes are
`1400000000000000017a5200017810011b0c070890010000`.
This is a selected-index check, not a whole-binary function census.
The four-byte literal at #94 `0x20a058` and #115 `0x45a128` is `20 20 20 20`.
The previously retained complete [#94 adapter disassembly](../RE-005-diagnostic-field-trace-94/observed/adapter.objdump.txt)
and [#115 helper disassembly](../RE-014-node115-field-adapter-drift-review-20261031/1686bd0.objdump.txt)
are the reviewable native row streams. This packet re-exported both from its
authenticated full files with GNU objdump 2.44, Intel syntax and the exact
bounds above. Independent official LLVM 19.1.7 outputs are retained as
[`node94.llvm.asm`](node94.llvm.asm) and
[`node115.llvm.asm`](node115.llvm.asm), SHA-256
`983395bd24fae9914753601a04b404de338da416bd1b18ec62d3c2d7e9835497`
and `517790acaea555a3414bcadf2cf2d3112503c4050d9fbaae997e91af5055fdf2`.
GNU and LLVM instruction starts, widths and raw bytes agree at all 176 #94
instructions/622B and 173 #115 instructions/630B. Python 3.12.14 performed
the selected-FDE and site checks; decoder agreement alone is not a semantic
proof.

## Qualified result and domain

For paired runs with the same valid immutable input bytes and initial
newline-state byte, nonwrapping pointer/length arithmetic, stable callback
context/vtable and newline-state pointers within each run, and normally
returning SysV AMD64 callbacks that preserve callee-saved registers and do not
mutate the input or later-needed metadata, these helpers have the **same ordered logical
callback requests, state writes and low-byte `AL` result (0/1)**. Logical
requests identify indentation or payload and its corresponding byte slice and
context; they do not assert identical numeric addresses, registers or stack
traces across releases. This cross-release equality additionally requires a
common abstract callback oracle: each corresponding logical request must get
the same low return byte and the same newline-state mutation. It does not
assert identical native writer identity or vtable addresses. A callback returns
zero for success and nonzero in
`AL` for failure. The helpers set `AL` on failure without promising that the
higher bits of `RAX` are cleared. Callbacks **may mutate the newline-state
byte** through its valid pointer. Each helper samples the current byte before
each nonempty piece; an indentation-success mutation is overwritten by the
helper's pre-payload store, whereas an indentation-error or payload mutation
persists. On successful payload, that mutation controls the next piece's
indentation. This admission still requires separation from input, frame,
callback metadata and return state. No result is claimed for other aliasing,
faults/unwinding, nonreturning callbacks, concurrent mutation, invalid slices
or nominal type identity.

The common trace rule is: split the input at the first LF in each remaining
slice, including that LF in the payload. Before each nonempty payload, read the
current newline-state byte; when nonzero, first call the writer with the four
spaces. If indentation fails, return 1 without the payload or a state write.
Otherwise set the state byte to whether the payload's last byte is LF, call the
writer with that payload, and return 1 if that call fails. An empty remainder
causes no callback or state write and returns 0. A successful nonempty payload
continues from its end. This is an observable helper contract within the
domain above, not recovered original Rust source.

## Native path correspondence

| Operation | node #94 VA | node #115 VA | Static relationship |
| --- | --- | --- | --- |
| Cache state pointer / callback context / vtable | `0x157d02f..0x157d046` | `0x1686bf5..0x1686c0c` | Same three `[rdi+0x10]`, `[rdi]`, `[rdi+8]` reads and stack slots. Vtable method `[V+0x18]` is loaded freshly for **each** call. |
| Remaining-length threshold | `0x157d0dc..0x157d0ea` | `0x1686cac..0x1686cba` | `remaining <= 15` selects byte scanning. |
| Scalar LF scan | `0x157d100..0x157d112` | `0x1686cd0..0x1686ce2` | Compare one byte to `0x0a`, advance until first match or end. |
| Aligned prefix | `0x157d120..0x157d12b`, `0x157d190..0x157d19c` | `0x1686cf0..0x1686d05`, `0x1686d70..0x1686d7c` | Prefix `((cursor+7)&~7)-cursor` is scanned bytewise. #115's moved `movabs` at `0x1686cfb` preserves the preceding `sub` flags for `jne 0x1686d05`. |
| Wide scan | `0x157d140..0x157d178` | `0x1686d20..0x1686d58` | Two 8-byte loads per 16-byte step, identical `0x0a` xor / `0x0101010101010100` subtract / `0x8080808080808080` candidate algebra after register mapping. A possible candidate enters scalar fallback from that block; no candidate advances 16. |
| Scalar tail/fallback | `0x157d1b0..0x157d1ce` | `0x1686d90..0x1686dae` | Scan to first LF or end. Candidate false positives do not change which LF is selected. An LF clears a candidate bit in the corresponding byte, so it cannot be skipped. |
| End selection | `0x157d1d0..0x157d216` | `0x1686db0..0x1686df6` | Found end is LF index + 1; no-LF end is input length; zero remaining bytes skip callbacks. |
| Optional indentation | `0x157d216..0x157d249` | `0x1686df6..0x1686e21` | Read state byte, call `[V+0x18](D, four_spaces, 4)` if set. `test al,al` and `jne` return 1 before payload on failure. #94 spills/restores cursor R8 across this call; #115 keeps cursor in callee-saved R15. |
| Payload / continuation | `0x157d060..0x157d0a3` | `0x1686c30..0x1686c74` | Store `last_byte==0x0a` **before** `[V+0x18](D, slice_start, slice_length)`. `test al,al` controls the failure `jne` despite intervening flag-preserving moves; later `mov eax,[saved continuation]` supplies the next loop's separate `test al,1`. |

Register map at the scan/callback boundary: scan cursor R15→R14, emitted
cursor R8→R15, saved input length `[rbp-0x68]`→`[rbp-0x60]`, and wide-scan
constants R14/RBX/R13→R12/R13/RBX (LF/one/high-bit mask). #94 reserves
`0x48` stack bytes and #115 `0x38`. Different register/stack scheduling,
block placement and constant load placement explain observed code motion in
the claimed paths; byte length alone was not used to infer behavior.

The wide-scan skip argument uses the actual instructions. Each 8-byte word is
XORed with repeated LF bytes. For an LF byte, the per-byte subtract result has
its high bit clear; the OR operand at that position (`original` in the first
word, XORed in the second) also has its high bit clear. Thus that bit cannot
equal the all-high-bit mask, forcing the scalar fallback. Other bytes can also
force fallback; that only adds scalar work. Both helpers use the same expression
and search the fallback from the start of the candidate block. The aligned
prefix and trailing bytes are always scanned bytewise, covering all bytes.

## Frozen synthetic controls

The first 26 `VECTORS.json` cases were frozen before the initial abstract
checker; eight later callback-mutation expectations were frozen before adding
that model branch. The resulting 34 cases
cover lengths 0, 1, 7, 8, 15, 16, 17, 31, 32 and 33; input pointer residues
0..7; LF at positions 0, 7, 8, 15, 16, 31 and 32; consecutive LF; high non-LF
bytes; initial state zero/one/two; first/later indentation and payload
failures; and callback state mutations on success and error. The Python test
checks 272 labeled abstract traces against the frozen
expectations. Its high-level scanner partitions synthetic input into prefix,
16-byte blocks and tail and uses `bytes.find`; these examples do **not**
independently prove cross-release behavior and do not run or emulate captured
instructions. The cross-release claim rests on the native CFG/dataflow
correspondence above. Separately, exact native site checks cover marker,
load width, alignment, stride, branch, state store, method load/call and
error propagation on both bodies. In-memory one-byte changes at every
selected site are rejected below full-identity admission; any change to the
rest of either body is rejected by the complete-body hash. These controls
check packet bindings and boundary expectations, not runtime equivalence by
experiment.

The existing independently authored
[`node94-newline-writer-protocol`](../../../src/node94-newline-writer-protocol/README.md)
is a bounded Rust model of this same callback-request relation for #94, with
dynamic `Cell<u8>` updates. This packet's new #115 native CFG argument is the
reason it can be reused for the #115 logical protocol within the domain above;
the pre-existing #94 tests alone do not establish that transfer. No duplicate
Rust implementation or original ABI claim is added. The unchanged model's
3,023-case test passed when freshly compiled under the existing authenticated
rustc 1.94.1 at both `-C opt-level=0` and `-C opt-level=3`.

Reproduce the selected static tests from repository root with the pinned
captured artifacts present:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -I -B -m unittest discover -s tests -p test_node_padadapter_semantic_comparison.py -v
PYTHONDONTWRITEBYTECODE=1 python3 -I -B -O -m unittest discover -s tests -p test_node_padadapter_semantic_comparison.py -v
objdump -d -M intel --start-address=0x157d000 --stop-address=0x157d26e artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x1686bd0 --stop-address=0x1686e46 artifacts/node/115/hl-node
/workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump --disassemble --x86-asm-syntax=intel --start-address=0x157d000 --stop-address=0x157d26e artifacts/node/94/hl-node
/workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump --disassemble --x86-asm-syntax=intel --start-address=0x1686bd0 --stop-address=0x1686e46 artifacts/node/115/hl-node
RUSTC=/workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin/rustc
for level in 0 3; do
  "$RUSTC" --edition=2021 --crate-name node94_newline_writer_protocol --test \
    -D warnings -C overflow-checks=on -C opt-level="$level" \
    src/node94-newline-writer-protocol/lib.rs \
    -o "work/re014-padadapter-semantics/node94_protocol_test_opt$level"
  "work/re014-padadapter-semantics/node94_protocol_test_opt$level"
done
GIT_CONFIG_COUNT=3 \
GIT_CONFIG_KEY_0=filter.lfs.clean GIT_CONFIG_VALUE_0='git-lfs clean -- %f' \
GIT_CONFIG_KEY_1=filter.lfs.smudge GIT_CONFIG_VALUE_1='git-lfs smudge -- %f' \
GIT_CONFIG_KEY_2=filter.lfs.process GIT_CONFIG_VALUE_2='git-lfs filter-process' \
make verify
make catalogue-check
make reproduce
(cd research/work-items/RE-014-node115-padadapter-semantic-comparison && sha256sum -c MANIFEST.sha256)
```

No captured program, instruction emulator, new compiler installation,
network service or live chain was run. The existing pinned Rust compiler ran
only on the independent #94 source and tests. The isolated worktree's initially
missing source submodules were filled from existing local checkouts only,
after checking all seven commits against the superproject pins. The
`can1357-hl` LFS working copy was matched byte-for-byte to the authenticated
node #94 artifact and its detached signature; no remote fetch or setup was
attempted. The inherited local Git config lacks the standard LFS clean filter;
`verify_imports.py` builds a fresh Git index and otherwise misclassifies the
hydrated, exact LFS object as a modified reference. The exact command-local
filter invocation above changes no persistent config and performs no fetch.
With those settings, `make verify` passed all eight artifact hashes, three GPG
signatures, 38 imported files and pinned source repositories. `make
catalogue-check` and `make reproduce` passed. The focused tests passed 3/3
normally and 3/3 under `-O`. The full current 972-file test suite was not
run on this worktree/head. An earlier local broad run passed files 1–7, then
was interrupted during file 8; its log is `/tmp/re014-make-test.log`. In that
worktree's default `PATH`, prior direct runs of the mandatory
`test_short_string_alias.py` and `test_visor_rust_unwind.py` failed in
`setUpClass` with `FileNotFoundError` at `tools/short_string_alias.py:56`
and `tools/visor_rust_unwind.py:104`. Official LLVM 19.1.7 was already
installed outside that `PATH` and was used for the dual-decoder check above;
these failures do not establish a missing LLVM installation or a failure of
the current-head suite. The coordinator's separate baseline suite is reported
separately and does not validate this packet's exact tree. Publication
remains pending; no milestone gate is requested.
