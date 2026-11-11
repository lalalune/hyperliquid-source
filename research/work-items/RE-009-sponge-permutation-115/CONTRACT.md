# Frozen complete200byte permutation, RE-009 / foundation

Node115 SHA256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
105896032bytes, base05bc2de303c05525b71e7e257426e741bc66a390.
Actual complete FDE5cda380..5cda902,1410bytes/354instructions. Incoming RDI
addresses one valid readable/writable200byte state, separated from writable
stack/redzone and readonly192byte round table94c518..94c5d8. Nonwrapping,
stable storage and ordinary instruction execution are premises, not a recovered
allocation or public Rust ABI. The caller's larger sponge state is not this API.

Input and output are ALL200raw bytes, interpreted as25little-endian u64 lanes
for the independently authored owned Rust API. No bytes, pointer differences,
padding or inactive fields are normalized away. Native evaluator uses actual
RET/restoredRSP and six distinct callee-saved register canaries, admits stores
only to state200/stack, checks surrounding state canaries, requires every output
byte actually written and known. Constants are exact readonly target bytes.
Original registers/stack not initialized by these premises stayunknown.

The complete body has no CALL. Its original round counter starts0, advances8
and compares against192; the actual table LEA/read is retained. Actual state
permutation and 24round constants are independently compared to a mathematical
Rust construction after a Git-sealed native freeze. LFSR-derived FIPS202
constants agree with every captured table word; this does not recover the
original library revision, compiler flags or complete digest API.

Independent algorithm reference: NIST FIPS202, sections3.2/3.3:
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
Coordinate convention: lane[x+5*y],64bits; the mathematical steps use column
parities, cyclic lane rotation/reindexing, nonlinear rows and round injection.
This source will be authored from that public mathematical specification, not
copied inferred Rust or library source. Keccak Team's specification summary is
an additional primary explanatory reference, not a recovered dependency pin:
https://keccak.team/keccak_specs_summary.html

Only the REX.W ROL forms missing in the existing instruction machine are added
inside this packet. Their count is masked to6bits; zero preserves flags; CF
receives resultLSB; ZF/SF stayunchanged; OF is known only for a1-bit rotation.
Actual immediate/one-bit forms are separately exercised. This is a bounded
ISA evaluator addition, not a complete x86 verification claim. Shared tools
remain unchanged; original missing-rotate failure is preserved. Intel reference:
https://cdrdv2-public.intel.com/782156/325383-sdm-vol-2abcd.pdf
The primary search excerpt confirms the64bit six-bit count; older primary
manual text explains rotate CF/OF and unaffected flags:
https://pdos.csail.mit.edu/6.828/2018/readings/i386/RCL.htm
Full modern PDF fetch exceeded the browsing tool's size limit; no successful
complete manual download or formal ISA proof is claimed.

This is a permutation ONLY, not an absorb/finalize/padding/digest, serialization,
preimage, signature, bridge request or state-root implementation. Existing
RE-017-abci-result-digest-115 maps its sponge callers and constants but explicitly
leaves the complete permutation unproved; that packet remains unchanged and
credited. No first-party or component byte-percentage credit, Rust original
ABI, whole-node correctness, cryptographic assurance, or full acceptance gate.
Actual callers' external helpers, data ownership, live reachability and library
license/version/build closure remain open. All92gates/registeredwindows stayfalse.
