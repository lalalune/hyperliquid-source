# RE-014 / RE-012: Node115 HTTP shutdown normalization and completion writes

Component: foundation, HTTP network-client dependency support. This is bounded
static research for the active node115, not a Rust implementation, a product bug
fix, or a claim that the HTTP driver/task/component is complete. All progress
gates stay false. Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

Target: Linux x86-64 node115, 105,896,032 bytes, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses below are original ELF link-time VAs, with no load bias.

## Question and prior work

Does the shutdown caller still propagate every encoded OS error, and what does
its HTTP completion site actually write? Historical node94 packet
[#1804](https://github.com/lalalune/hyperliquid-source/pull/1804) supplied a
search lead, not evidence for115. Its wrapper prefix has zero115 matches. This
packet resolves the115 shutdown import and fresh callers, CIE/FDE extents,
classification call, local field and output writes without importing94 offsets.

The classifier `0x5cdf1b0` is already covered by
[#2032](https://github.com/lalalune/hyperliquid-source/pull/2032), head
`499a60329a205d6cc61de669f420227d5c41a608`. It is **shared context**, freshly
validated here to close the selected caller's class7 dependency, not a new
classifier recovery. The new observations concern the shutdown wrapper and its
inline HTTP use. This packet does not implement that PR's accept4 family or
change its files. #2028's runtime entry/callback ranges are also separate.

## Observations

1. `.rela.dyn` identifies `shutdown` at slot `0x64e06a0` and
   `__errno_location` at `0x64dffc8` (type6). Both selected call sites resolve
   through these actual symbols; similarity to a historical byte pattern is
   insufficient. A preliminary scan found11 direct RIP-relative `.text` calls
   to the shutdown slot; that scan is a lead count, not a complete call graph.
2. In the83-byte unwind range `0x5ce0b30..0x5ce0b83`, fd is read at local
   `[rdi+0x18]`. fd=-1 branches away before the syscall. At `0x5ce0b39`, ESI=1;
   the imported shutdown call is at `0x5ce0b3e`. On EAX=-1 the code loads errno
   and forms `(u32(errno)<<32)|2`, then calls `0x5cdf1b0`.
3. `0x5ce0b61` compares raw AL with7. Class7 calls `0x5cdf710`, then clears
   EBX at `0x5ce0b6d`. Other classes branch directly to `0x5ce0b6f` and retain
   encoded RBX. The ordinary return sets RAX=0, RDX=RBX. Thus the wrapper's
   raw return pair is `(0,0)` for syscall success or this ignored class, and
   `(0,encoded_errno)` for other error classes. These are register observations,
   **not** a recovered Rust enum ABI or a claim about all helper side effects.
4. Shared classifier context: lowtag2 selects `0x5cdf1ca`; the122-entry signed
   displacement table at `0x94c7b4` maps only raw errno107 to `0x5cdf207`
   (`b0 07 c3`). Its entry is at `0x94c95c`. The input index is
   `u32(errno)-1`; unsigned indices above121 use raw default41. The checker
   binds the entire table and both imported symbols, not only the selected cell.
   No Rust error-kind names are inferred from raw integer7.
5. Cleanup range `0x5cdf710..0x5cdf7de`: EDI low2 bits are masked, then
   unsigned `(tag-2)<2` branches at `0x5cdf723` to the ordinary epilogue at
   `0x5cdf72a..0x5cdf735`. For the selected encoded OS lowtag2 this path has
   no object dereference or external call. Other boxed variants/deallocation/
   unwind paths are outside this semantic claim.
6. In the HTTP driver unwind range `0x2b018e0..0x2b05403`, inline shutdown at
   `0x2b04517` uses local `[r15+0x18]` and ESI=1. After syscall failure,
   `0x2b04535` calls the same classifier; `0x2b0453a` compares7 and
   `0x2b0453c` sends other classes to `0x2b046f5`. Class7 calls cleanup at
   `0x2b04545` and rejoins the syscall-success path at `0x2b0454a`.
7. At the completion site `0x2b0455d`, old `[local r15+0x1c0]` is loaded to
   RAX, then cleared at `0x2b04564`. If old RAX is zero, `0x2b04578..0x2b04584`
   writes raw output tag0 through the pointer at `[rsp+0x78]`. Otherwise
   `0x2b04572` reaches `0x2b04941`, writing raw tag2 at output+0 and the old
   RAX payload at output+8. This is a local branch observation; R15 has other
   definitions elsewhere, so no entry-object layout is asserted.
8. Other error classes save RBX at `[rsp+0x38]` (`0x2b046f5`). One direct route
   reaches `0x2b04938`, passes RBX to the opaque indirect call at `0x2b0493b`,
   and stores that call's RAX using the shared tag2 site. **No claim that the
   retained field stays untouched on all error paths**: a conservative direct
   CFG from `0x2b046f5` can also reach its clear instruction. Branch feasibility,
   tracing effects, error-wrapper semantics, callbacks and unwind are unresolved.

HTTP attribution is an inference: RIP-relative data references inside the
selected driver reach actual RELATIVE-relocated source-path data containing
`z_forks/hyper-fork/src/proto/h1/conn.rs` (e.g. instruction `0x2b03480`) and
vendor hyper connection paths. They do not establish an exact crate version,
original source ownership, or that the whole15,139-byte range is one function.
No unlicensed inferred source was used.

## Reproduce

From repository root, with the authenticated pinned LFS input materialized:

```sh
python3 -B research/work-items/RE-014-http-shutdown-115/verify.py
python3 -B research/work-items/RE-014-http-shutdown-115/controls.py
# Optional fresh export: native GNU objdump2.47 and Capstone distribution5.0.9
python3 -B research/work-items/RE-014-http-shutdown-115/capture.py --objdump objdump
```

`verify.py` is stdlib-only, using the unchanged repository ELF/CIE/FDE parser.
The public CLI always checks the whole target size/SHA before observing bytes;
there is no identity-bypass option. It checks exact semantic anchors, direct
callee displacements, RIP-relative GOT calls, dynamic symbol relocations,
classification data, complete extent hashes, CIE/FDE/LSDA metadata and every
exported address/raw-byte pair against both native exports. It never executes
or emulates captured code. The fresh-export command writes ignored `work/`.

Original exports used native GNU objdump with
`-d --wide --insn-width=16 -M intel --start-address=<start> --stop-address=<end>`
and Capstone x86-64 mode, Python3.12.1 on Windows. Distribution5.0.9 reports
wrapper5.0.7/API5.0. These versions are distinct in `records.json`. Only the
local target filename in GNU's display header is sanitized; instruction bytes
and operands are untouched. New code/docs are MIT. Target-derived disassembly
is evidence of the pinned imported artifact and retains upstream rights; it is
not independently reconstructed machine code.

## Denominators and controls

Four complete **unwind-described** ranges total15,620 bytes /2,904 decoded
instructions: driver15,139B, shutdown wrapper83B, shared classifier192B,
cleanup206B. All2,904 Capstone/GNU address/raw-byte pairs agree, no masks.
This is a decoder/export-integrity comparison, not compiled-source equivalence.
No source-to-target comparisons are registered; no reconstructed-byte credit or
whole-module/function denominator is requested. Unwind ranges can cover split
code and do not prove true whole-function boundaries.

The7 control tests include13 actual capture-byte corruption subcases: shutdown
how, class7 branch, result register, shutdown/errno GOT call, classifier/cleanup
call, cleanup tag dispatch, field offset/clear, output tags, errno107 table.
Additional controls alter a real dynamic symbol, export byte, instruction gap,
FDE end and CIE encoding. They call the internal observer directly, so an outer
whole-file SHA mismatch cannot be the reason these semantic controls pass.
These controls validate evidence sensitivity, not runtime behavior.

## Results and limits

Initial exact-byte verification and all7 corruption tests pass. On the unchanged
base, `make doctor` passed; `make verify` checked all6 artifact sizes/digests and
then failed native GPG public-key import (exit2, agent path/name-too-long under
`--no-autostart`). A separate official `gpgv` authentication of the pinned
node115 signature passed with fingerprint
`CF2C2EA3DC3E8F042A55FB6503254A9349F1820B`. This is **not** a replacement pass
for `make verify`. Final-head official command outcomes are reported in the PR;
no hosted CI/container success is claimed here. No pinned import, generated
catalogue, progress record or runtime policy is modified.

Not implemented/measured: Rust reconstruction, whole-driver CFG/dataflow,
tracing/error-wrapper closure, all shutdown callers, vtables, boxed cleanup,
full caller ABI, integrated node behavior. The next question is to resolve
`0x2b0493b` and feasible error/tracing paths before implementing a completion
adapter; do not infer `Result`/`Poll` variants from raw tags alone.
