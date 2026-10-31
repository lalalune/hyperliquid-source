# Static scan and pretty-route proof

The observed contracts below are implemented by the digest-bound producer and its adapter certificate module. The initial published flat-only files and evidence remain preserved at Git commit 61e91dbc1bd7bfbb4dbfb09e5b655f028a9b57f9. All claims are conditional and all component gates remain false. Read ASSUMPTIONS.md with this proof.

## 1. Claim and denominator

Close a conditional static normal-return contract for the field helper's pretty route and its actually used writer adapter, while retaining the published flat contract. The two FDEs total 1,012 bytes / 285 native rows: helper [0x1571f50,0x15720d6), 390 bytes / 109 rows, and adapter[0x157d000,0x157d26e), 622 bytes / 176 rows. Node #94 SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f remains the sole target. This is no progress-gate, physical-rendering, recovered nominal Rust type/ABI or runtime-equivalence claim.

The adapter's FDE 0xcfb300 / CIE 0xce1518, raw bytes, 176 native rows, 23 conditional branches / nine jumps/two indirect writer sites/oneRET are bound in observed/records.json (used_adapter_contract). The only calls are 0x157d081 and 0x157d23a, both through a currently read +0x18 method entry of a cached vtable pointer. There is no direct shared panic/lifecycle dependency.

## 2. Parent pretty route

Let S be entry RDI, F=load64(S), E=byte(S+8), H=byte(S+9). The shared E!=0 route remains unchanged. The proposed new domain is E=0, sampled byte(F+0x12)&0x80!=0, H in {0,1}, and the callback/memory conditions below.

H=0 requests the original writer's three-byte opening 207b0a at 0x1572031 and stops on nonzero AL; H=1 skips it. R12b is reset to 1 at 0x157203a after preserving/restoring incoming name arguments around the opening callback. This reset, not an assumed callback result representation, supplies subsequent failure status.

At0x1572045..0x1572070, local byte N at rbp-0x29 is initialized to1. Local A at rbp-0x70 receives the current 16 bytes at F+0/F+8 plus pointer to N at A+16. Local L at rbp-0x58 receives pointer A, actual descriptor VA 0x5674210 and the current qword at F+16. In H=0 these samples occur AFTER the opening callback. The mode branch used the earlier sampled mode bit; no preservation of F contents across that callback is silently assumed.

Name and colon requests call fixed slot 0x576e330 -> adapter 0x157d000, with A and the actual incoming name slice or colon 3a20. The value callback receives incoming data via saved rcx, local L in RSI, and saved incoming descriptor+0x18. Its nonzero AL is normalized to error 1. If it returns zero AL, the suffix call reloads L+0/L+8 and requests 2 bytes 2c0a. Identifying that last target with adapter 0x157d000 requires preserving the local L metadata and its descriptor; the primitive fact is the actual fresh reload.

Nine mode-set E=0 normal-return routes are already enumerated in observed/records.json (pretty_contract.normal_return_paths): one H=0 opening-error route and four name-error/colon-error/value-error/suffix-normal routes for each H value. All require actual ordered S-save/status-definition/storeS+8/storeS+9/pointer-return/RET witnesses. No output is attached to RET merely because it is a RET. Success suffixAL is captured at 0x15720ce. Under the proven adapter specialization its low result byte is 0/1; higher RAX bits and nominal Result layout are not claimed.

## 3. Adapter entry bindings and phase names

Use p for incoming slice pointer, n for its byte length, B=load64(A+16) for the flag pointer, D=load64(A+0) for destination and V=load64(A+8) for vtable pointer. All three pointer VALUES are cached at entry in rbp-0x50/-0x48/-0x40. The+0x18 method entry itself is read anew at each callback. Input p and n are retained in rbp-0x30/-0x68, and p+8 in rbp-0x58. These are observed native slots, not Rust layout claims.

At loop-header0x157d0a3 with continuation d=0, emitted cursor e=R8 and scan cursor s=R15 satisfy e=s and 0<=s<=n; constants HI,R13 and LFWORD,R14 are restored. Initially e=s=d=0. If d's low bit is 1, the preceding final-tail request succeeded and the helper returns AL=0 BEFORE using any stale emitted cursor. Do not require e=s on that d=1 exit: the final-tail payload restores an old e into R8 and deliberately exits before reusing it.

A valid newline piece is nonempty. A no-newline final tail is nonempty only if e<n. An empty input or empty tail after a terminal newline exits at 0x157d214/259 with no callbacks and no flag-byte dereference/write, although A's pointer fields were loaded at entry.

## 4. Scanner proof

At search setup, m=n-s and a=p+s. Immutable valid input and nonwrapping address/length arithmetic are explicit conditions.

### Scalar path

For m<=15, RSI starts at 0, compares byte(a+i) with0x0a BEFORE incrementing i, and iterates while i<m. Thus its first matching index is the smallest LF in[0,m); no match means the whole interval has no LF. The actual equal/less-than/zero-length guards must be bound to their raw operands and destinations.

### Alignment and two-word path

For m>15, delta=((a+7)&~7)-a is in[0,7]. If nonzero, bytes [0,delta) are checked by the same compare-before-increment scalar order. After that prefix, a two-word check is entered only if t<=m-16, initially t=delta(or 0 when aligned). Otherwise the remaining suffix is scanned bytewise.

Each wide iteration reads exactly[a+t,a+t+8) and[a+t+8,a+t+16), as established by the p+8 saved pointer and load displacements-8/0. These intervals are in bounds by t<=m-16. The skip stride is exactly16. After a certified skip, t+=16 and the loop repeats only if t<=m-16. A candidate or a short remaining tail falls back to a scalar scan starting at t. Previously skipped/prefix bytes contain no LF, so that scalar scan still returns the first LF of the entire remaining input.

The wide skip predicate is derived from the actual constants and operations, not a native instruction interpreter. Let U64 operations wrap modulo2^64, C=0x0101010101010100, LFWORD=0x0a0a0a0a0a0a0a0a, HI=0x8080808080808080, xj=wj XOR LFWORD:

  T0=((C-x0) OR w0) AND HI
  T1=(C-x1) OR x1
  skip iff (T0 AND T1)==HI.

Only the no-false-negative implication is needed: skip implies neither word containsLF. If any byte ofwj is0x0a, the corresponding byte ofxj is0. At byte0, C's byte is 0 and incoming borrow is 0, so the subtraction byte is 0. At higher bytes, C's byte is 1 and incoming borrow can only be 0 or 1, giving byte 1 or 0. Its high bit is 0 in every allowed borrow case. OR with either original LF 0x0a or xor-zero leaves that high bit0. Thus the combined predicate cannot equal HI if either word containsLF. False positives are allowed because candidate blocks fall back to exact scalar scanning. Mechanize these finite byte-index/borrow cases after authenticating the extracted constants, and retain the complete algebraic argument.

The chosen LF has absolute index j=s+i<n. The two rechecks at 0x157d1da/1e3 confirm bounds and equality before committing to a chunk. Their retry branches are structurally present but unreachable under the established bound and immutable-input conditions; do not silently claim behavior under concurrent input mutation.

## 5. Chunk progress and callback/state transfer

A newline piece ends at t=j+1, with e<t<=n. The next scan cursor and next emitted cursor are both t, and d=0. This establishes strict progress. A no-LF final tail ends at n and has d=1; if e=n it returns immediately. Consequently successful iterations are bounded by the number of LF bytes plus at most one nonempty tail and one empty-tail check. No captured loop execution is used to establish this bound.

For each nonempty piece, the exact order is:

1. Save the continuation word at rbp-0x34 and read the current byte through cached B.
2. If nonzero, call the current +0x18 method of cached V, with cached D and the four-byte slice at VA 0x20a058(bytes 20202020). Nonzero callbackAL returns AL=1 without the current piece's flag store or payload request. The helper itself has not changed N in this piece yet.
3. Compute whether the selected piece's last byte isLF; store that 0/1 byte through B BEFORE calling the payload writer. Request the actual slice [p+e,p+t), with cached D and currently read method entry of cached V.
4. Nonzero payloadAL returns AL=1 after that flag store. Otherwise restore scan state/constants and reload continuation d. At0x157d087 the TEST of payloadAL supplies flags for JNE0x157d09d; the intervening MOVs reload EAX and other registers without modifying those flags. A witness must bind this chain explicitly.
5. If d=0, reestablish e=s=t at the header. If d=1, return AL=0. Failure path0x157d25d writes only AL=1; higher RAX bits are not a general result value.

The selected-end==old-e branch at 0x157d249 can request an empty payload in other machine states, but it is unreachable under this proof's valid-input progress invariant: LF pieces have t>e, and final-tail t=e exits earlier. Keep that conditional distinction visible instead of erasing the branch from the raw CFG.

## 6. Conditions and exclusions

Reached callbacks return normally and preserve the callee-save registers plus protected frame/control/saved-argument slots. All actually accessed memory is valid. The input bytes remain unchanged during one adapter invocation, with no relevant pointer or length wrapping. Writes through B or callbacks do not corrupt the input, vtable/data needed later, frame or return state. A's fields are readable even with n=0; flag memory need only be accessed on a nonempty request.

The primitive contract records cached pointer values, fresh method-entry loads and the ordered PRE-callback flag store. To infer stable writer identity, separately require method-entry preservation. To infer a final N value, separately require writer callbacks to preserve N. In the parent, value callbacks may use local L and update N through the adapter protocol, but known suffix dispatch requires preservation of A/L metadata. Caller writes/aliases violating these conditions are unqualified. No physical rendering, original Rust layout/type/ABI, memory safety, arbitrary callback effects, application reachability or complete source equivalence follows.

## 7. Retained meaningful controls

Fresh native decodes of copied byte mutations must retain operand/CFG consequences, rather than fail only an image hash or count check. Actual controls include:

- Parent H/opening branch or literal/length, N initialization, A/L setup/copy and value formatter argument, value-error handling, suffix slice and result capture; directRET and partial-common-output variants must still reject missing witnesses.
- Scalar LF 0x0a->0x0d with inputLF/CR boundary witnesses; first/last byte and empty/trailing-LF cases.
- Wide threshold15->14, which admits a 16-byte read with only 15 bytes available; load displacement and stride16->32, which produce a demonstrable unchecked interval containingLF.
- Wide LFWORD/C/HI changes: extract the changed arithmetic certificate and retain an actual mathematical false-negative witness where possible. For example a wrong LFWORD can skip an inputLF; a zeroed higher C byte with incoming borrow1 turns its newline subtraction byte into 0xff. This is finite arithmetic over words, not target instruction emulation.
- Four-space pointer/length, cached flag/destination/vtable arguments, flag-store destination/source and order, indent/payload error branches, AL failure constant, and the payload TEST/MOV/branch flag chain.

Compare proof certificates against independent byte/interval/segment expectations at lengths 0/1/7/8/15/16/17/31/32/33, every pointer residue modulo 8, LF at word/block boundaries and arbitrary non-LF high bytes. No real callbacks or captured code are invoked. Original failed checker evidence must remain preserved.

## 8. Implementation and verification scope

The producer is tools/bincode_diagnostic_field_static.py. Its focused mathematical certificate module is tools/bincode_diagnostic_adapter_static.py. Source witnesses and all rows are tied to authenticated raw bytes; there is no target instruction interpreter. The proof record carries 15 borrow cases, eight alignment residues, branch/operand relations and all 176 adapter row roles. The scalar/interval/progress argument above supplies the general proof; finite boundary vectors corroborate implementation of the certificates.

Both source modules, both test modules, controls.py, pretty_controls.py and the complete packet are covered by MANIFEST.sha256. All 29 focused tests and 58 actual raw-byte controls passed. Exact tool/input/source identities and proof/native export hashes are in INPUTS-AND-TOOLS.json. Independent final review and all required checks on a frozen committed head are reported separately; no hosted CI, Rust, runtime, layout or gate success is implied by these local results.

Physical-flag precision: no B-directed access on an empty slice is a protocol fact. An unchanged physical N additionally requires separation from all own prologue/frame/return writes, not only writer callbacks. D/V/B are the actual values loaded after the prologue, rather than presumed pre-prologue memory contents. The parent direct-call N is above the adapter private frame; generic or nested calls still require the stated separation conditions.
