# RE-009: the exact `/dev/null` route in one state-dump body, node #94

The accepted `RE-009-storage-state-roots` packet explicitly leaves open what
happens after its `/dev/null` comparison succeeds. This packet answers that
control/dataflow question for **one** body: the match jumps over the ordinary
path-dependent call chain, then joins shared downstream work and the common
32-byte output copy. It is **not an early return from the whole function** and
does not establish absence of external effects.

The complete selected FDE is `0x46cea60..0x46cf026`, **1,478 bytes / 299 native
instructions**, with 28 calls, 33 branches and one `ret`. Its twin at
`0x46cfe90` and every callee body are excluded. No reconstruction gate or
whole-program coverage/equivalence claim is requested.

## Provenance

- Task/component: RE-009, storage; source-attributed `l1/src/abci/state.rs:145`.
- Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Node #94: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Body file offset: `0x46cda60`; SHA-256
  `807fa711fa39db4b04f99097ec2f2609e61adee3f28d9883a47fbff99d018c1e`.
- FDE `0x127e83c`, CIE `0xfbdc2c`, LSDA `0xb6ac1c`. Actual FDE field
  arithmetic is checked independently against the existing record walk and
  the `.eh_frame_hdr` entry. An index stride is not used as body size.
- No unlicensed inferred implementation was copied or used as a semantic
  oracle. Existing accepted binary evidence supplied the question and source
  attribution; all new transfers are independently read from the target.

## Exact predicate and continuation

Input words at entry `RSI+0x10/+0x18` are loaded as a pointer and length at
`0x46ceacf/0x46cead3`. The length is compared with 9 at `0x46ceae1`; unequal
length goes to `0x46ceb0e`. For length 9, the first eight bytes are XORed with
`/dev/nul`, the ninth byte is zero-extended and XORed with `l`, and the two
results are ORed. The `je` at `0x46ceb08` targets **`0x46cec83`**.

For accessible input regions, the XOR/OR result is zero exactly when both
pieces match. Together with the length test this recognizes only the nine
bytes `/dev/null`, not a prefix, suffix, case-folded spelling or trailing NUL.
This is an exact byte predicate, not a filesystem-path normalization rule.

The collector independently recomputes every direct branch destination from
its encoded displacement, matches the native operand, and requires an actual
instruction boundary inside the selected body. Its basic-block partition
covers all 299 instructions. The records distinguish two ordinary cases:
unequal length and equal length with unequal bytes. Their possible normal
call sets agree; their common destination is `0x46ceb0e`.

## What is bypassed and what remains

The normal graph treats a call as a normally returning edge and leaves later
data-dependent branches unconstrained. Under that model:

| Call-site class | Count | Interpretation |
| --- | ---: | --- |
| Common | 8 | Reachable on both exact-null and ordinary routes |
| Ordinary only | 14 | Bypassed by the exact-null branch |
| Not reached from normal entry | 6 | Retained cleanup/exception-region calls; not declared dead |

The counts are **possible call sites**, not numbers of calls guaranteed to
execute for an input. Repeated execution, helper non-return and exception
feasibility are not proved.

Before the comparison, calls at `0x46cea7c` and `0x46ceac1` remain on both
routes. The latter receives an output-buffer pointer `RSP+0xe0`, with relative
target `0x326aec0`. Its actual implementation and effects are not analyzed.

The ordinary-only region includes the path-bearing call at `0x46ceb14`
through slot `0x576f620`, two alternatives at `0x46ceb62`/`0x46cec00`, and
calls at `0x46cec39` and `0x46cec5e`. Immediately before `0x46cec5e`, RDI/RSI
receive prepared words, RDX/RCX receive the retained path pointer/length, and
R8 receives Location `state.rs:145:17`. Its actual relative target is
`0x144c560`; no filesystem-write, serialization or syscall contract is assigned
to that helper here. Ordinary-only error/diagnostic routes are also retained,
including the `state.rs:145:35` Location and a visible `ud2` at `0x46cef85`.

The null branch reaches the shared join at `0x46cec83`. Six later common call
sites remain possible: `0x46cec98`, `0x46cecda`, `0x46ced31`, `0x46cee2e`,
`0x46cee4a`, `0x46ceeb1`. Some depend on subsequent branches. The call at
`0x46ced31` receives `RSP+0x60`, whose last visible direct stores were the
path pointer/length. This does not establish that the helper performs a
filesystem operation or that other helpers could not mutate aliased storage.

### Used output, rather than a default-return inference

The upstream call receives `RSP+0xe0` before the predicate. A later explicit
store at `0x46ceac7` writes the retained word from `*(entry RSI)+0x28` into
`RSP+0xf8`, the fourth word in that 32-byte region. The original output pointer
is saved at `RSP+0xc8`. The common tail `0x46cee50..0x46cee6f` loads the
two 16-byte chunks at `RSP+0xe0/+0xf0` and stores them through that saved
output pointer at offsets 16 and 0 before the sole normal return.

These are actual pointer/field transfers. They establish neither a private
Rust output type nor a default value. The buffer's contents at the tail,
including preservation across intervening helpers, remain conditional on the
alias/ABI assumptions below.

## Relocations and exceptions

All 15 selected `R_X86_64_RELATIVE` records are retained with original bytes,
file offsets and addends: called slots, both source-Location slots and the
personality slot. Location pointer bytes in the file are recorded separately
from their relocated addends. The two source records resolve independently to
`l1/src/abci/state.rs`, line 145, columns 17/35.

The original CIE/FDE and LSDA prefix are retained. The LSDA has 11 call-site
intervals, with a nonzero action index in one interval and an encoded type
table. The collector associates calls using **return PC minus 1**; some calls
have no interval. It does not infer nounwind from an absent interval, interpret
the type/action/personality semantics, or claim that cleanup blocks are dead.
These records remain separate from the normal-entry graph.
The bounded graph also stops at the FDE end. Its final cleanup call's return
behavior is unclosed; a missing in-scope successor is not a proof of noreturn.

## Reproduce

Python 3 standard library and GNU objdump are required; recorded exports use
GNU binutils 2.44 on Linux x86-64. The complete ELF is authenticated before and
after analysis. Native objdump receives only a private, read-only **1,478-byte
raw slice** with the original virtual origin; it never reopens the ELF
pathname. No large target copy is made. Only the private pathname in native
headers is normalized to `<authenticated-selected-code>`; numeric addresses,
bytes and operands are preserved.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/state_dump_null_route_static.py \
  --output /tmp/state-null-new
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest tests.test_state_dump_null_route_static -v
(cd research/work-items/RE-009-state-dump-null-route-94 && sha256sum -c MANIFEST.sha256)
make doctor verify test catalogue-check reproduce
```

Use a new output directory. Same-toolchain exports must repeat byte for byte;
normalized records are compared across compatible GNU versions allowing only
the version string to differ. Raw text equality across different versions is
not asserted.

Tests check all single-byte alternatives to the matched path and length/shape
boundaries. Actual literal and JE-to-JNE counterfactuals change the extracted
classifier or the used call set **before** local rejection; the latter changes
the exact-null normal call set from 8 to 22 sites. Other controls alter actual
field/copy bytes, every selected RELA addend, a direct call, a branch into an
instruction interior, CFI/Location/LSDA fields and the whole target identity.
A real native-reader control replaces a supplied input pathname after the
ELF mapping is acquired: GNU still reads the private admitted slice. Altered
bytes are never accepted as Node94 or executed.

## Assumptions and limits

Calls must return normally and preserve the native ABI's callee-saved
registers/frames for the stated normal dataflow. Input/output regions must be
valid and live. Helpers may receive escaped pointers and may alias/mutate
buffers; their effects and concurrency are unclosed. Thus this is a static
branch/call/argument/copy contract, not a guarantee of no I/O, successful
execution, a particular output value, or a drop-in Rust API.

The captured binary, filesystem operations, compression/upload commands,
networking and chain actions were never executed. No Rust implementation,
runtime comparison, hosted CI result or gate change is claimed. The next
semantic prerequisite is the effect contract of a specifically used opaque
helper; generic helper ranges and private type guesses do not close it.
