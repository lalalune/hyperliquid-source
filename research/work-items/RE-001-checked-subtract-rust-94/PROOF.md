# Checked subtraction, ordered operand aliases and unconditional rewrite

Target node94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Complete leaf ELF VA `[0x2760a10,0x2760a67)`: 87 bytes/27 instructions. RDI=output O, RSI=subtrahend S, RDX=minuend A. The names describe operand roles; original types and source identity are unknown. The separate reconstructed leaf 0x32d8310 is not this function.

## Ordered reads and arithmetic

Let B=2^64. The four minuend qwords occupy disjoint consecutive ranges in the admitted nonwrapping 32-byte operand region. Let a_i denote their entry values. At stage i, let b_i be the qword at S+8i after the preceding lower minuend stores. The first three stages subtract b_i and the incoming borrow from a_i and immediately store the residue at A+8i. Because S may overlap A at arbitrary byte displacement, b_i need not equal the entry-memory subtrahend word. Preloading all four b_i would be wrong.

Set c_0=0. For i=0,1,2, let d_i=(a_i-b_i-c_i) mod B, c_(i+1)=1 iff a_i<b_i+c_i. SUB/SBB implements this relation. MOV does not change carry. The qword load of a_3 occurs after the first three writes and before reading b_3, but the prior minuend writes are disjoint from its range, so it remains its entry value. The top b_3 read sees all three lower writes.

The top sequence intentionally separates two borrow conditions. It computes h=(a_3-b_3) mod B, then uses the captured c_3 in AL: ADD AL,255 sets CF exactly when c_3=1. Thus d_3=(h-c_3) mod B and CL records only h<c_3. CMP a_3,b_3 and JB separately detect a_3<b_3; neither condition alone is sufficient. Their union equals a_3<b_3+c_3, including b_3=B-1,c_3=1. The top residue is stored before either check. Therefore all 32 minuend bytes are rewritten on both success and failure.

Define the effective 256-bit right operand T=sum(b_i B^i) and entry left L=sum(a_i B^i). The standard prefix invariant gives the staged result D=(L-T) mod B^4 and success iff L>=T. This does not assert L minus the entry right value when operands alias. Each b_i is defined by the ordered memory relation above.

The independent oracle evaluates this invariant using arbitrary-precision whole-prefix subtraction: after observing b_i it writes the lower 8(i+1) bytes of L-T_i modulo B^(i+1), where T_i contains the observed right words. Rewriting that entire prefix leaves earlier lower results unchanged and exposes the same memory to the next observation. No native flags, instruction dispatch or captured code execution is used. Rust uses bounded byte overlays and limb arithmetic instead.

## Output, final image and RAX

On success, two MOVUPS loads snapshot all 32 already-rewritten minuend bytes before either output copy. The high 16 bytes are stored at O+24, then the low 16 bytes at O+8. Their destination ranges are disjoint; even when they overlap A or S, both store sources are already snapshots. The final qword store at O writes 1 on success and 0 on failure. Failure performs no output-payload copy, though the unconditional minuend rewrite or flag can overlap those same bytes. “Output payload untouched on failure” is true only when those stores do not alias it.

RAX is cleared with XOR EAX,EAX before the checks; success loads EAX=1. The flag store and RET preserve it. Complete raw RAX is exactly the same 0/1 flag. No outgoing call or branch leaves the bound leaf. The two failure branches reach the common final flag store. No RIP-relative data access exists.

## Safe image domain and transactional refusal

The API uses one mutable byte slice at an abstract u64 base and integer A/S/O addresses, not host pointers. The image, both 32-byte operand ranges and each actually used output range must be nonwrapping and mapped. All operand bytes are read in every normal execution; output requires 8 bytes on failure, 40 on success. Alignment and disjointness are not required. Arbitrary operand/output overlap within the image is admitted.

A staging buffer initially holds the entry minuend. A right-byte read consults that buffer if its address lies within the minuend, otherwise entry image memory; previously written lower limbs are updated and unmodified upper limbs retain their entry bytes. This gives exactly b_i above without writing the actual image. Success is then known and its conditional output range can be checked. Only after all required ranges pass does the API apply the planned minuend rewrite, the two output snapshots on success, and final flag. Every safe refusal leaves the entire image unchanged. This preflight is an explicit API behavior, not a claim about native fault timing or prefix effects on a fault.

Native correspondence assumes ordinary stable valid memory and valid disjoint instruction/control storage. Fixed operand/output formation that wraps, faults, MMIO, concurrent access, flags, unobserved registers and the native pointer ABI are excluded. The changed physical access schedule is not an architectural trace claim; the proof establishes final data bytes and raw RAX on the admitted domain.

## Static context and scope

Three direct sites 0x2760924, 0x276095c and 0x2760998 reside in the complete caller `[0x2760040,0x2760a04)`, 2,500 bytes. Full target, FDE/CIE inventory, caller body and instruction boundaries, nine padding bytes, direct E8 census and complete relocation scan are independently revalidated. The first call supplies `(O,S,A)=(RSP+0x60,RSP+0x160,RSP)` and checks the dword flag at RSP+0x60. The second supplies `(RSP,RSP+0x180,RSP+0x40)` and tests its output byte flag. The third supplies `(RSP+0x1b8,RSP+0x140,RSP+0x60)` and returns to a common output-handling block. These are ordinary local data buffers within the caller frame, disjoint from the callee RET control slot under the native validity premise. They ground use of the stored flag and result without inferring broader caller algorithms. The bridge block-step packet referenced this helper without claiming it; its captured-code emulator is neither read nor used here. No whole-node equivalence or progress gate is claimed.
