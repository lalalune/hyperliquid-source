# RE-001: node115 post-field result and closing-delimiter adapter

Component: foundation. Base `05bc2de303c05525b71e7e257426e741bc66a390`.
Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105896032 bytes,
SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses below are original ELF virtual addresses, not runtime addresses.
New analysis/scripts are independently authored MIT; no inferred private source
or reference implementation was copied.

## Question and resulting evidence

Which bytes determine the return and whether a final delimiter is emitted after
this owner passes `Error` and field `kind` to formatting callbacks? The preexisting
RE-014 field-adapter packet establishes its helper correspondence, but does not
explain this owner's stack/result adaptation. This packet closes that bounded
caller question; it does not reconstruct the opaque field value or writer.

The complete actual FDE is `0x14ca3f0..0x14ca4a1`: **177 bytes, 47 native
instruction rows**, `.eh_frame+0x7844`. `evidence.json` includes every raw body
byte, complete FDE bytes, its decoded pcrel range, selected data, LEAs, branches,
call edges and relocation records. `owner0.objdump.txt` retains every instruction,
including both epilogues. No byte or operand is masked; only the temporary input
path in native output becomes `<authenticated-node115>`. Padding is excluded.

## Observed local data flow

At entry save original `RDI` at stack+0x18 and original `RSI` in RBX. The
first call uses `[RSI]` as RDI, literal `Error` (`0x4645e7`, length5) as RSI/RDX,
and the function word at `[[original RSI+8]+0x18]`. Its return AL is stored at
stack+0x10, and byte stack+0x11 is initially zero. There is **no early branch
around the following field helper** based on that AL.

Call at `0x14ca43e` goes through actual RELATIVE slot
`0x64dfad0 -> 0x167d950`, the field caller studied in
`RE-014-node115-field-adapter-drift`. Its arguments are:

| Register | Observed argument |
| --- | --- |
| RDI | stack+0x08, initially holding original RSI |
| RSI / RDX | literal `kind` at `0x459f20`, length4 |
| RCX | address of saved original RDI at stack+0x18 |
| R8 | descriptor at `0x63f8ea0` |

The selected descriptor method slot `0x63f8eb8` is an actual RELATIVE relocation
to `0x15ea550`. That value/formatting body is opaque here. This owner is different
from the tag-text dispatcher `0x14ca4b0`; neither its method nor the field helper
points to that dispatcher. Table shape is observed; original trait/type is not
established by a pointer or a literal name.

After the helper normally returns, read **post-helper** byte `c=stack[0x10]`,
byte `h=stack[0x11]`, and (only in the close branch) pointer `p=stack[0x08]`.
The helper received this stack region, so the initial prefix AL and original
RSI must not be substituted for these post-helper values without proving the
helper's writes.

The local condition at `0x14ca450..0x14ca457` is
`((~h | c) & 1) == 0`. Equivalently, close only if lowbit(c)=0 and
lowbit(h)=1. Otherwise the owner returns lowbit(c|h), without a closing call:

| lowbit(c) | lowbit(h) | Local next action |
| --- | --- | --- |
| 0 | 0 | return0 |
| 0 | 1 | closing callback |
| 1 | 0 | return1 |
| 1 | 1 | return1 |

On the closing branch, test **post-helper** byte `[p+0x12] & 0x80`.
Zero selects `" }"` at `0x46e92e`, length2; nonzero selects `"}"` at
`0x46e84c`, length1. Both pass `[p]` and call `[[p+8]+0x18]`. The final
callback AL is explicitly ANDed with1 before the owner returns. No result
meaning, full EAX value, callback success convention or helper side-effect
closure is inferred from this bit test alone. Both callback effects remain
external to the packet; all continuing statements assume normal return.

`algebra.py` exhausts all65536(c,h) byte pairs to verify only the Boolean
identities above. It does not execute/interpret instructions, supply opaque
helper results, or implement a target formatter.

## Reproduce, before/after, and controls

From repository root, with Python3.11 and native Apple LLVM objdump (version
output retained verbatim in evidence):

```sh
python3.11 -B research/work-items/RE-001-node115-format-result-adapter/collect.py --negative-controls
python3.11 -B research/work-items/RE-001-node115-format-result-adapter/collect.py --output work/format-adapter-fresh
python3.11 -B research/work-items/RE-001-node115-format-result-adapter/algebra.py
```

`--output` requires a new directory; optional `--objdump PATH` selects an
installed LLVM objdump. Full target identity is checked before analysis or
native export. Native export reads a private byte-identical authenticated
snapshot under ignored work/, never executes it, and proves disassembly covers
exactly all177 body bytes with no duplicate coverage. Compare fresh
`owner0.objdump.txt`, `frames.json`, `evidence.json` byte-for-byte to this packet;
algebra stdout equals `algebra.json`. Two independent fresh local exports matched
all3 outputs exactly. Verification stdout equals `validation.json`.

Before: the owner/result/closing rule was not recorded by this packet or the
existing helper packet. After: complete owner bytes/FDE plus explicit helper,
stack-byte and branch evidence establish the local relation, with missing
helper semantics retained. No reconstructed Rust or before/after target run is
claimed.

The18 actual corruption controls are recorded individually in validation.json:
1 full-image identity rejection;10 instruction-anchor,4 data,1 FDE and2 actual
RELA corruptions. For the latter17 the test deliberately bypasses **both full
and body hash gates and retained-disassembly comparison**, reaching independent
exact operand/data/range/binding checks. These demonstrate static admission
checks, not semantic mutation execution or an independent target oracle.

## Limits and acceptance

No captured execution, emulation, source build, instruction interpreter,
callback invocation, chain/network action or unlicensed source was used.
Original ABI/types, caller reachability, opaque helpers and unwind behavior are
unresolved. This is one bounded static owner, not foundation coverage or a
complete type reconstruction. All component gates and byte-coverage totals
remain unchanged/false. **Required full suite was not run**: its default oracle
producer is outside this task's static authorization. This contribution is for
a **DRAFT PR**, pending maintainer-arranged compliant full validation; local
static checks do not satisfy that missing gate or prove hosted CI.
