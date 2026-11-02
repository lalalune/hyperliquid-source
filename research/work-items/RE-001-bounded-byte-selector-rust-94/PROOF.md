# Closed byte selection and full-register equality

Target node94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Complete ELF VAs: selector `[0x4ff8ac0,0x4ff8b28)` (104 bytes/32 instructions), wrapper `[0x5004e70,0x5004ea1)` (49 bytes/13 instructions). All addresses are linked ELF VAs, not guessed runtime rebases. These names describe observed behavior; no original source/type identity is established.

## Selector: all paths and width transitions

Let B=2^64, U=2^32. Entry RDI and RSI are address values A and S; I=low32(RDX), K=low32(RCX), F=low8(R8). Let signed32(x) map residue x in 0..U-1 to x if x<2^31, otherwise x-U. Reads below are from stable entry memory M.

1. If F=0, return 0 without any input-memory read. XOR EAX,EAX already zeroed full RAX before the flag branch.
2. Read cached byte C=M[S+340]. If C!=255, read W=LE32(M[A+20..A+24]). If signed32((W-1) mod U) <= signed32(I), return C. The subtraction is 32-bit and wrapping; CMP overwrites its flags before signed JLE. If C=255 the W field is not read.
3. Read H=LE64(M[S+464..S+472]) and L=LE64(M[S+456..S+464]). If H=L as full 64-bit values, return M[S+339]. Neither address L nor H is dereferenced in this case.
4. If I=0 as a full u32 value, return M[L]. This shortcut comes after the empty test and before relative-index arithmetic.
5. Otherwise define d=signed32((I-K+1) mod U), e=signed32((H-L-1) mod U), and t=max(0,min(d,e)). Return M[(L+t) mod B].

Step 5 follows the width changes literally: SUB RAX,RDI computes a 64-bit span, but SUB $1,EDI truncates to low32 and zeroes RDI's upper half. CMP/CMOVG compares d and e as signed i32. MOVSLQ sign-extends the chosen value for the candidate address; TEST EDX/CMOVG uses that address only when the chosen value is strictly positive. For zero/negative values L remains selected. Therefore the candidate computed for a negative value is never dereferenced and can be omitted in the value projection. H-L need not describe a positive or valid array span; its low32 residue, together with the full64 empty test, is the established rule. H itself is never dereferenced.

Every successful return zero-extends a byte into full RAX: flag zero uses XOR EAX; a cache hit retains MOVZBL's EAX; default/data paths end in MOVZBL EAX. No success path returns a pointer or nonzero high RAX bits. There are no input-memory writes or outbound calls in the selector.

## Wrapper closure

The wrapper snapshots inner=LE64(M[O..O+8]), I=LE32(M[O+8..O+12]), and K=LE32(M[inner+2800..inner+2804]), and calls the selector with `(A=inner,S=O+904,I,K,F=1)`. K is loaded before the call even if the selector's eventual path does not use K. Afterwards it compares the selected byte with M[O+4116], then SETE AL.

Because the now-closed selector guarantees RAX in 0..255, all upper bits are zero before SETE. Thus the wrapper returns full RAX 1 on equality and 0 otherwise. The historical packet's arbitrary callee-result examples established only a low-byte relation while the callee was unknown; they are not evidence that this actual callee can return values above 255. Closing the call establishes the stronger full-register result. The wrapper's PUSH/POP and CALL/RET affect control-stack memory only, excluded from the observed data-image projection.

## Safe API and access domain

Both public APIs read one immutable byte image at an abstract u64 base. Addresses are integer values, never dereferenceable host pointers. The selector accepts arbitrary u32 I/K and u8 F; these preserve exactly the native argument bits used. The wrapper accepts O and derives its arguments from the actual fields above. Results represent the complete raw RAX values (selector byte, wrapper Boolean), not an inferred machine ABI.

Flag-zero selection returns zero before validating any image mapping or argument address because no data access occurs. Otherwise the image must not wrap; fixed field-address additions must be nonwrapping and every actually accessed byte range must fit. Only selected paths' reads are required. In particular: C=255 skips A+20; a cache hit skips all span/default/data reads; equality H=L does not require either address mapped; a nonempty span may select a valid computed byte even if L itself is outside the image. The L+t addition retains its observed modulo-B arithmetic. Only the final selected byte is validated. The wrapper additionally requires its eager K field and final comparison byte.

Unavailable required ranges are refused rather than faulted. The image is never written. Native faults/permission timing, volatile/MMIO memory, concurrency, stack/control/data aliases, fixed-field pointer wrap, unobserved registers and original pointer ABI are excluded. For native correspondence the abstract image's actual accessed ranges represent valid ordinary target memory and are disjoint from valid native control storage. No claim is made that every u64 abstract mapping is available to a Linux process. No enum, positive-length, sortedness or ordinary bounded-array premise is invented.

## Independent oracle and static closure

The oracle evaluates the piecewise mathematical selection relation, using arbitrary-precision residues and interval conversion rather than instruction/register simulation. It freezes 4,716 target-derived inputs and exact raw-return expectations before Rust exists. The original oracle and corpus remain unchanged. A separately identified 24-case post-Rust wrap supplement addresses a surviving checked-add mutation; its direct address equation and unchanged-oracle cross-check are in `supplement.py`, with provenance in `COMMANDS.md`. Native clients receive only those inputs. Source uses explicit wrapping u32 arithmetic and signed comparisons; it contains no copied inferred implementation or captured bytes.

The internal call at 0x5004e91 is closed by the selector, which has no calls. All jumps stay inside their respective bodies; neither body has a RIP-relative static-data dependency. Complete caller/FDE/CIE bytes are bound independently by GNU and LLVM. Full text scanning finds nine selector sites and one wrapper site; each is a decoded boundary in the retained window. The wrapper's caller `[0x50070f0,0x50073c7)` passes its object at 0x50071c9 and consumes the low-byte Boolean. The other seven external caller FDEs are shared static context with the gated-block-copy packet, whose distinct body 0x4ff8b30 is not reconstructed here. Their broader algorithms remain unclaimed.

All 80,300 RELA records are checked; none has either entry as addend and none overlaps the bound code windows. Direct E8/addend scans are not a complete indirect-reference census. The new contribution reconstructs only this closed selector/wrapper pair; it does not claim whole callers, source identity, whole-node equality, native target execution or a progress gate.
