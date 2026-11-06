# RE-012: listener limiter counter updates and strict over-budget return

Transport allocation through the actual consensus listener caller. Sole node115
SHA256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
105896032bytes, base05bc2de303c05525b71e7e257426e741bc66a390. This is one
bounded static RE-001/RE-012 question about595ec00, the explicitly opaque limiter
in merged #2628. Existing source-Location packet about59db700/59db990 measures
different bodies and proves no policy here. No Rust or runtime-oracle claim.

## New observations, separately from context

New helper FDE595ec00..595f2d7 is1751bytes/400instructions. Complete caller2af8be0..2af9c09
is4137bytes/727instructions of credited #2628 context, not an extra reconstructed function. GNU,
readelf, independent Python ELF/FDE/RELA and Capstone records bind complete
exports. Addresses are ELF VAs, raw bytes unnormalized. Full FDE is an export
denominator, not complete semantic closure of every helper/error branch.

Actual direct calls2af8f42/2af8fda pass this helper RDI=callerfield+0xb8,
RSI=callerfield+0xc0+16, RDX=20bytekeytemporary, RCX=class-specific raw amount,
R8=10000/1000000 and R9=12byte date-like input. Neither class names nor time units
are recovered. The normal caller takes AL==0 to subsequent dispatch; AL!=0
follows its rejection route. Prior address/decoder admission remains #2628.

The helper searches a20byte-key tree using u16nodecount+0xe6, childtable+0xe8 and
rawdepth. A comparator equality arm clears EBP and returns before lock, date
conversion, callback or counter access. The memcmp load slot64dfb50 binds the
import name, not its runtime pointer. Ordinary callee ABI preservation and normal returns are conditional premises, not callee proofs. Native tree/container validity and the
imported comparator's ordinary contract remain premises; no complete tree
reconstruction or membership security claim follows.

On the nonmatching/empty-tree arm, CMP/ADC changes rawRCX=0 to1 and preserves
other raw amounts. This is a minimum charge of1, not an ordinary truthiness test.
The lock byte has an actual0->1 CMPXCHG and a separate slow helper. On normal
release a1->0 CMPXCHG runs, with its own slow path. This shows ordering only,
not race freedom or proof of lock/poison semantics.

A date-like packed three-DWORD input is converted through integer arithmetic,
then the resulting signed value is clamped below at0. The unsigned division
uses state+0x160 as divisor, with separate32/64bit DIV arms. A zero divisor and
invalid date encodings are not assigned behavior here. A strictly larger quotient
is stored atstate+0x168 before5617fc0. That helper remains opaque, so this is not
proof that an epoch resets counters or that the divisor is milliseconds.

Afterward, the function pointer freshly loaded fromstate+0x170 receives a full
20byte key copy. Its nonzero AL skips the counter path and produces localAL0.
No identity, allowlist or predicate implementation is invented. If AL0, R8budget
is doubled and LEA-scaled to10*budget modulo2^64, without an overflow branch.
The fixed supplied budgets10000/1000000 do not overflow, but arbitrary rawbudget
wrap must not be confused with saturation. A hash helper4e52940 and raw Swiss
control/key scan select or create a40byte row; their allocation/hash and
container invariants remain open.

The row cursor points just past its40bytes. Before later threshold helpers,
row[-16] receives unsigned-saturating(old+max(rawamount,1)); row[-8] later
receives a saturating increment. These are actual separate stores with an
intervening helper opportunity, not an atomic pair or rollback contract.
The early floating comparison converts the accumulated u64 with the retained two-lane constants, but converts wrapping10*budget with signed CVTSI2SD before multiplying by state+0x10. Its UCOMISD/JBE takes the non-callback arm on equality or unordered; a strictly ordered-greater relation can call4ef8440 onstate+0x1d8. Original MXCSR/NaN behavior and units are not closed. The following
rawstate+0x30 minimum-word sentinel suppresses another callback branch. Otherwise
10*budget is multiplied bystate+0x48; a high-half overflow skips that branch,
as does currentcharge<=product. This secondary helper call atstate+0x178 is
not the final admission result. Formatting/callback effects remain unclosed.

Finally the charge is RELOADED after those helpers and compared unsigned with
the wrapping10*budget. Equality takes localAL0. Strictly greater calls4ef8a10
onstate+0x1a8 and sets BPL=1. That helper's AL chooses additional reporting work,
not whether this local result is1: both branches retain1 through normal unlock.
A later minimum-word sentinel atstate+0x80 can skip reporting, also without
changing that selected localAL1. Because helpers may change memory or unwind,
these observations do not compose a pure whole-function limiter equation.

## Evidence and controls

The collector's exact instruction groups bind selected definitions, arithmetic,
flags, displacement widths, callback gates, saturation stores, final reload and
branches, plus both actual caller argument preparations. Operand-derived fields
include mincharge1, wrappingbudgetfactor10 and20byte comparator width. Twenty-three selected instruction groups and three16byte readonly context records are bound. Each
counterfactual below the target identity gate changes an actual selected byte
and must be structurally rejected. These controls authenticate static evidence;
they are not native output changes, differential execution or Rust equivalence.
Synthetic scalar boundary tables separately illustrate only the decoded local
math. No opaque helper returns are supplied to make a complete trace.

```sh
python3 research/work-items/RE-012-peer-limiter-counter-policy-115/collect.py --output work/peer-limiter-replay --check
python3 -m unittest discover -s tests -p test_peer_limiter_policy115.py -v
```

New code uses root MIT; collector ELF/FDE/GNU scaffolding is credited to the
project's RE-004-node115-fee-scaling packet. Existing #2628 and rate-coordinate
packets, captures/imports/tools/pins are preserved. Unresolved callback targets,
clock validity/units, hash/container/resize, object aliasing, concurrency,
allocation/drop, panic/unwind, integrated transport and code-byte equivalence
remain open. No public vulnerability, runtime rate guarantee, captured execution,
network/service, signing, chain action, Cargo graph or component gate claim.
Next close the specific epoch helper and counter-row construction before a
stateful Rust implementation can safely compose this caller policy.

Initial collection passed70.863s. Its actually loaded collector is archived separately; the final collector adds explicit readonly-data/version records and is freshly replayed before submission. These are static records, not pre-Rust expectation or equivalence claims.

Final collection73.515s passed: GNU/Capstone full instruction agreement and
Python/readelf FDE/RELA agreement;1751B400instructions newly examined plus
4137B727instructions credited caller context. The new helper has16actual calls,
including2register-indirect unresolved runtime targets, and43direct branches.
23instruction groups+3readonly records yield26structural rejection controls;
224explicitly local scalar illustration rows are not native execution vectors.
Seven focused tests passed7.229s under serialduty0.10 (not strict aggregate CPU
cap). The collector includes Python/Capstone/GNU version records. Initial and
final collection source/version distinctions are retained; no earlier successful
run is relabeled as having the later metadata.

Catalogue/check alone uses already-submitted #2655 authenticated snapshot-read
fix for the measured39.47GB repeated-read blocker. Baseline helper is restored
before actual reproduce/final audit and remains unchanged in commits. This is
not an unmodified-head local catalogue claim. Full repository make test/new-head
hosted CI is pending. Exact replay and integration results follow below.

Integration422.291s passed: six generated native/record/version files byte-exact on fresh replay69.140s,12packet-integrity tests, doctor/verify, disclosed catalogue/check overlay, baseline helper restoration and actual reproduce. Earlier7focused tests remain unchanged and passed. New-head fullCI pending.
