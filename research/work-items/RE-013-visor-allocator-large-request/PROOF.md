# Conditional static proof

This is a reviewed instruction-family certificate and integer argument, not an
x86 interpreter, theorem-prover completeness result, allocation model or target
execution. All coordinates below are linked ELF virtual addresses. Every row
in the five fragments is bound by a raw operator/register/control signature;
variable immediate fields are independently extracted. A family counterfactual
may have a different certificate and is never an authenticated target.

## L1: entry gate and physical state

Let S be the architectural entry RSP, B the architectural FS base at the
relevant sample, r the entry RDI unsigned word, and T the value actually read
from FS+0. Valid readable/executable immutable image, readable selected inputs,
usable own frame and normal instruction completion are premises. Six pushes
and `SUB RSP,0x98` give local RSP P=S−200. The six saved-register slots occupy
`[S−48,S)` and the hardware return slot `[S,S+8)`; intervals must be usable and
nonwrapping. The saved guard is written at `[P+0x88,P+0x90)=[S−64,S−56)`.

The code saves r in RBP, loads T into RBX, then adds −0xc80 to RBX. It separately
loads the architectural guard at the actual FS+0x28 and writes its saved slot.
The byte comparison at `0x70a1ac` uses FS:[−0xc80+0x330] = FS:[−0x950]. This
is the value sampled after those prologue writes, not an assertion about the
pre-entry byte. Do not infer T=B or a private TLS layout. Arithmetic below uses
no RBX cache contents. Any alias effects must satisfy the actual sampled gate
and validity/physical preservation premises; no broad nonalias/purity theorem
is hidden here.

A nonzero sampled byte branches at `0x70a1b4` to opaque `0x70a450` before any
request bound. This packet makes no global oversized-request rejection claim.
With zero byte, unsigned `CMP RBP,0x1000; JA` reaches `0x70a620` iff r>4096.
The REX.W CMP sign-extends its imm32; the observed immediate is positive4096.
The family checker rejects negative immediates instead of treating them as
unsigned32 thresholds. For this large route, no runtime class map is read.
Small requests fall outside the selected proof domain and may use that map.

## L2: bounded native arithmetic

The maximum is extracted from `MOVABS R13,0x7000000000000000`. `CMP R13,RBP; JB`
branches to `0x70a43c` iff unsigned r>M. Otherwise 4096<r<=M<2^63. Thus
`w=2*r−1` is positive and less than2^64, the native LEA does not wrap, and BSR
has a defined highest-set-bit result k=floor(log2(w)). Its range is13..63.

The selected operator sequence establishes:

- ECX=max(7,k), then ECX subtracts3; shift s=k−3 is10..60, so x86 shift-count
  masking does not change the mathematical amount.
- R15=r−1, RDX begins all ones, then `(RDX<<s)&R15`, logical right shift bys,
  and `AND EDX,3`. For0<=s<64 the result is `t=((r−1)>>s)&3`.
- R10D is max(6,k)=k. The actual LEA SIB scale is4 and signed displacement−23,
  giving R14D=c=4*k+t−23. No intervening call clobbers r or these terms.

## L3: complete interval lemma

For each integer k>=3 and t in0..3, set u=2^(k−3). Exactly the integer requests
in `[(4+t)*u+1,(5+t)*u]` satisfy both floor(log2(2*r−1))=k and
`((r−1)>>(k−3))&3=t` within the k band. The four quarters partition
`[2^(k−1)+1,2^k]`; adjacent bands and adjacent quarters meet without overlap or
gaps. Intersecting them with `[4097,M]` therefore proves the entire domain,
not only endpoints, without enumerating individual requests.

For k13..62 all four quarters survive. At k63, M=7*2^60 removes quarter3 and
ends quarter2, so 50*4+3=203 intervals remain. Their classes ascend29..231.
This fits the native unsigned32 LEA exactly. Consequently `CMP R14D,231; JA`
at `0x70a1db`/`0x70a1e2` cannot select the rejection path on this domain.
RBP=r and R14D=c reach the following opaque allocator body at `0x70a1e8`.
The later class-size table, allocation results and invariants are not implied.

The producer constructs the analytic intervals from observed guard/clamp/mask,
scale and signed-bias fields, verifies coverage and nonwrapping hypotheses,
and retains the full203 rows. Endpoint checks corroborate this general lemma.
Rust independently uses bit-length(r−1), which equals floor(log2(2*r−1)) for
integer r>=2, rather than evaluating the native instruction sequence. The Rust
runner's expectations use membership in the authenticated intervals.

## L4: oversized branch and conditional zero return

Under L1's sampled zero gate and r>M, `0x70a62d` branches directly to
`0x70a43c`. It calls opaque `0x7a68a0`; no retained exact-address symbol/FDE
name was found, and its code is not inspected here. Premises: the call returns
to `0x70a441` with P restored, subsequent selected instructions/reads/writes
complete normally, and its actual RAX=q permits the four-byte store. No GPR
preservation beyond the stated return/stack conditions is needed for the zero
result: the next instruction sets R12D=0 after the call.

`0x70a444` writes numeric12 as a DWORD through q, then the actual jump at
`0x70a44a` reaches `0x70a2b0`. The store does not establish errno, error kind,
callee purity, allocation behavior, absence of heap effects or preserved caller
data. q may alias other state; all stated physical postconditions still have
to hold after the call and store, including guard and saved/return state.

The epilogue reads `[P+0x88]`, subtracts the current architectural FS+0x28,
and the actual JNE selects opaque `0x70b743` if unequal. No claim is made about
that path. Assume physical guard equality after the opaque call/store, and
preserved, usable saved-register/return slots. Adding0x98 restores RSP=S−48.
The actual `MOV RAX,R12` at `0x70a2ce` occurs before POP R12, giving RAX=0.
Six pops restore the saved slots, then RET at `0x70a2db` uses the protected
hardware-return slot. All sixteen path witnesses, including exact branch/jump
targets, zero destination, store base/width, return source and stack release,
are bound. A skipped store/guard/return witness cannot receive this certificate.

This theorem is conditional on normal call/store/guard/frame/RET behavior, not
an original allocation API, all-path error policy, exception proof or run result.

## Caller relation and exclusions

Published #1040 head `eecb73baf1e9047b404c38e3d9527988f24eb721` derives
r=24*C without wrapping for its own qualified interval/resource domain.
Published #1045's held cache proof transfers r>4096 unchanged into this target.
Thus qualified C>=171 uses this large partition; C<=170 remains small. Qualified
C>=336268772176997035 would exceed M if such C is possible in that caller's
own domain. This conditional connection adds no caller bytes to our251-byte
scope and establishes no deployed occurrence, defect or fresh writable storage.

The other7,360 bytes, cache initialization, nonzero gate, small map, later
allocator body and all opaque helpers/canary failure remain open. No physical
layout/type attribution, Rust ABI, runtime or byte identity equivalence is
claimed. Every global component gate and pinned input remains unchanged.
