# Selected isolated same-table decrease: native bridge before new Rust

Node94 SHA256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Reviewed native freeze 9cbf05cc152e0912a31ca4d016c679f23a2381bf809663f180a3ece09b7d69f8
retains original byte freeze f5798585b7be758b86c7dd3565e3a26bfbc74c758dfde7af2843868de2fd15e0
binds ten complete FDE/CIE/LSDA/header identities and GNU=LLVM byte partitions:
8,450 bytes/1,856 instructions. Caller, position calculation and surplus are
credited existing RE-004/RE-007 context, not new full-function recovery. Selected
new closure is clone/row binding and its decrease branch. Allocator/deallocator
and recorder internals are explicitly not recovered. No target/interpreter runs.

## Qualified normal path

One custom registry table id>=50, matching existing position table, stable
validated nonempty1..3 MarginTable, canonical position mode word1, requested
cross=false, active position, positive requested u32 strictly below old u32.
Prior metadata/price indices pass. Positions tree has height0 and one entry
matching the requested asset. Companion tree is empty. All per-call live inputs and designated output slots satisfy the precise
preservation/alias premises below; there is no blanket ban on ancestor frames.

For the numerical normal path: price raw word is also a nonnegative i64;
signed size*price fits i64, and abs(notional)/requested fits i64. Other arithmetic
states are not mapped to native refusal tags: the observed lower helpers have
panic/assert/divisor paths. Allocator ordinary success returns a fresh disjoint
writable0x328-byte leaf; deallocator and overflow-recorders return ordinarily.
Those provider hypotheses, actual registry/user admission and postcommit
semantics remain unresolved. This is not an actual-chain admission vector.

## Explicit provider preservation and alias premises

For each call boundary c, define F_c as that callee own live activation/control region, including spills, stack temporaries, saved registers and return machinery. Readable inputs and explicit ancestor-frame outputs must avoid F_c and each opaque provider private region while live.

Declared outputs may intentionally occupy ancestor-frame slots: clone handles at caller sp+0x30, shadow account at sp+0x60, and position-margin output in the surplus helper frame. These are allowed designated writes, not forbidden generic frame aliasing; each must avoid other still-live values not designated for overwrite.

Opaque allocation/deallocation/overflow-recorder hypotheses require preservation of every subsequently used source/table/metadata/price/status word and saved value, plus ABI callee-saved registers and control machinery. Ordinary return alone is insufficient. No assumption preserves unspecified caller-saved registers beyond actual declared uses/returns.

Exceptions are only declared fresh-Q construction/write regions, free(Q) after last use, declared ancestor-frame outputs for their actual called helper, and provider-private allocator/recorder effects that do not intersect other live regions. Allocator/free/recorder calls may not overwrite a pending tag0x47, saved surplus/result, sources or table data.

Q must be fresh and disjoint from all other live objects, each callee own frame/control region and other designated outputs; original source and table storage remain stable through callbacks. No actual allocator/free/recorder behavior or general ownership/nonalias theorem is established.

The original intakes/semantic freeze are retained under review-original/. Only
reviewed premise wording/decoder metadata is rebound; all original input, expected
value, control and exclusion bytes are unchanged. These hypotheses are not a
claim about the actual providers. The original byte-intake script remains a
record of its earlier observations, not a generator for this review overlay.

## First-tier and cap prefix

Existing#1460 establishes that the SAME custom R15 holder supplies the first-tier
maximum and the position cap. Requested>maximum gives only tag0x43;
requested>cap gives tag0x50 and initialized u32cap at+4. For canonical mode1 and
cross=false, the DWORD mode gate passes. Kind byte is not rejected on this branch.
These early gates remain before the shadow calculation. Padding is not modeled.

## Exact one-leaf shadow binding

At370a07d..a096, a matching table does not take the table-change branch, but
requested<old does not take JAE370a090; it enters clone setup. R14 is the original
account row. 33ed7f0 receives its positions handle at original+8 and outputsp+30.
Length1/rootnonnull selects33eb860 with the original root P and height0.

33eb877/87a selects leaf branch33ebab9. It requests0x328 through slot576dfd8
(RELATIVE54c06b0). On the stated fresh/disjoint allocation Q, it writes parent0
atQ+2c0 and count0 at+322. The one iteration at33ebb10..99 copies the original
key fromP+2c8 toQ+2c8 and all64 value bytes: four16-byte loads at33ebb18..23,
then four16-byte stores at33ebb78..87. Count becomes1 and output rootQ/height0/
length1 is written at33ebba4..b5. Other unused node bytes are not claimed.

The companion wrapper33ed610 sees length0, writes root0/length0 at33ed634..3b
and leaves its unused height word unspecified. No nonempty companion clone
claim is made. Caller copies account fields and those two handles onto its
shadow atsp+60. The copied selected position retains mode+0, margin+8 and
size+10, including all their original bits.

Caller searches the cloned positions using the copied key. In this matching
one-leaf case it writes a found cursor (tag0,rootQ,height0,index0) at370a1a3..b7.
33bd420 tests cursor tag0 and takes33bd525: value address=root+64*index. It
returns Q without default-row construction, allocation, insertion or record edit.
Only caller writes370a21a/221 then change u32table at+38 and u32leverage at+4.
Thus original margin/size/mode and all other value bytes survive until the check.
No raw B-tree or Rust object ABI is exported as the proposed logical API.

## Mode1 and same price, not an injected surplus

Same table makes370a228/22b skip the mode2 call. requested<old reaches mode1
at370a25e..27a. Caller passes canonical !cross=1 in RSI, asset R12 in RDX,
ECX=1, R9=D+60 and stack argument D. 37d77e0's testSILbit1 therefore takes
its isolated branch, searches the cloned position and copies64 bytes at
37d78bb..78e2. Its96-stride price load at37d7908..7921 uses[D+68+96*local+20],
the SAME word used by the prior cap. Mode byte1 reaches3717480 through57746d8;
its five-entry jump table selects37174cb. Mode1 ignores the custom tier
requirement/cap operand and divides unsigned abs(notional) by NEW leverage.

Existing independently authored calculate_position_margin can supply this
normal relation without a new arithmetic helper:

N = signed size*same signed nonnegative price (checked)
A = clamp_i64(original margin+N)
R = abs(N)//new_requested_leverage, withR<=i64MAX
surplus = clamp_i64(A-R)

37d7947/94c read A at native output+0x08 and R at output+0x28.
The unsigned effective_margin at output+0x10 is NOT that requirement. Reuse
logical margin_after/computed_requirement fields, not effective_margin. The R high-bit assertion is outside
the qualified domain. Signed subtraction at37d78a4 uses the overflow-recorder
path to return its saturated result on ordinary return. This is the existing
assess_isolated_liquidation numeric subtraction relation; its liquidation name
does not make the caller's leverage predicate a liquidation action.

## Negative only and normal cleanup continuation

Caller TEST RAX/JS370a280/283 rejects strictly negative surplus. Zero is accepted.
For canonical cross=false,370a2eb..2f8 computes0x47^0 and writes onlyu16tag0x47.
Other status words/padding are not initialized here. Both paths call3761d10:
negative at370a300 then shared refusal cleanup; nonnegative at370a28a then
JMP370a28f to3709cfa. That endpoint remains EnterCommit, never action Success.

Selected shadow drop constructs an iterator with the fresh positions rootQ,
height0 and remaining count1. In33b4700, the first call decrements count to0,
forms a nonzero cursor and advances index0→1 without freeing Q. The second call
sees count0, reads parentQ+2c0=0 and height0, calls deallocation once with
(Q,0x328,0) at33b4a6d, and returns the initialized zero output marker. The outer
loop terminates. Companion drop33f2df0 tests its root0 at33f2dfe and returns at
33f300b without observing its unspecified height. This closes the selected
normal control path; allocator/free internals, generic drop/clone trees, unwind
behavior and global recorder effects remain unknown.

## Candidate evidence and implementation limits

Freeze independent gate decisions around surplus-1/0/+1, new versus old divisor,
long/short signed notional, integer flooring, margin saturation, cap/global gate
precedence and exact u32 fields before writing Rust. Reuse actual existing
position/surplus/cap functions; do not inject a precomputed surplus or maximum.
Keep domain refusals separate from native tags, and keep eventual EnterCommit
separate from all mutation helpers and final0x186. No financial/live action.
