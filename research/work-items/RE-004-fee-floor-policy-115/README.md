# RE-004: node115 fee floor construction, ternary math and late result gate

Fees, one bounded static question. Node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105896032bytes, base05bc2de303c05525b71e7e257426e741bc66a390. Merged
#2153/#2169/#2176 map the outer fee schedule but explicitly leave36a58d0
opaque. This packet examines that private helper, not the already mapped outer
ordering or generic math in isolation. No Rust/oracle/whole-gate claim.

## Measured scope and data flow

The private FDE36a58d0..36a5d40 is1136bytes. Five floating-helper context
FDEs total1240bytes: wrapper63f0210..63f0221, software candidate63f0230..63f0679,
FMA3form63f0680..63f0686, FMA4form63f0690..63f0697 and dispatch63f06a0..63f0711.
Only the private floor question is newly interpreted; context extents are not
additional first-party implementation credit. All complete bytes, FDE/CIE,
LSDA coordinates, GNU/readelf/Capstone partitions and dynamic bindings remain
separate. No exported-byte count is an execution/reconstruction percentage.

Incoming RDI points at a record whose+0/+8/+0x10 words point at three headers.
Each header has payloadpointer+8 and count+0x10. The first two nonempty headers
supply their LAST f64; an empty header substitutes record+0x18. The retained
CMPUNORDSD/MINSD/mask sequence selects the base. Its NaN/signedzero behavior
must not silently be replaced with a mathematical minimum; exact instructions
are retained, without a claimed portable min implementation.

Header3 supplies its first and last f64 when nonempty; otherwise record+0x20
supplies both. Let L be this selected last value, B the selected base, and
p28/p30/p38/p40 the f64 fields at those raw record offsets. Native scalar
operations explicitly form u=(1-p28)*L, v=(1-p30)*u, w=(1-p40)*v. A later
separate arm forms x=(1-p38)*u. This is ordered binary64 arithmetic, not an
algebraic reassociation or proof of original fee units.

The bound is the exact raw f64 at459388, displayed5e-6; its hexadecimal bits
are retained. The first ordinary lower comparison tests B+w. Four subsequent
ternary calls consume w with coefficient/addend pairs
(0.2,B*0.2),(6,B*6),(0.1,B*0.1),(2,B*2). Each observed call result is compared
against that bound. The later arm first prepares the w/40 pair, then five x
pairs for0.2/6/0.1/2/40, using the earlier saved B*coefficient addends. It checks
all these call results and B+x. In total there are10ternary calls and2plain
sum comparisons. No numerical result for an opaque call is supplied here.

Most lower failures use UCOMISD epsilon,value then JA: ordered epsilon>value
fails; equality passes. The first-stage last comparison uses JBE to the next
stage, including its unordered flag pattern. The subsequent JA guards likewise
do not reject unordered comparisons by themselves. This is a local flags fact,
not a claim that NaNs can reach from the outer finiteness gate or that SNaN/traps
and MXCSR are handled. Under exact real algebra these expressions might look
redundant, but replacing the actual ordered operations/ternary calls with one
reassociated inequality is unproved.

## Actual math boundary, without a fabricated implementation

Four direct RIP calls use slot64e0fd0; six register calls use R14 loaded from
that same slot. Its RELATIVE target is63f0210. That wrapper reads writable
cache64ffe00 and CALLs its current RAX target. The cache's initial RELATIVE
record points at63f06a0, not a permanent runtime callee.

The dispatcher reads a cached DWORD at6728920, conditionally invokes an
unclosed feature helper63f0730, and saves a flagged result. In the low cached
byte, bit6 selects63f0680 with priority; otherwise bit7 selects63f0690; otherwise
it selects63f0230. It stores the chosen address in64ffe00 before its indirect
tail jump. The two small targets contain VFMADD213SD and VFMADDSD respectively.
This grounds the fused ternary interpretation for those actual hardware routes;
software equivalence, CPU/OS feature admission, floating environment and races
on cached initialization remain unproved. We do not execute CPUID/AVX/FMA or
substitute the host's mul_add as an oracle. Software body bytes are context,
not claimed closed source or a recovered dependency/version/license identity.

## Passing these bounds does not finish the private helper

After the last floating comparisons, the body constructs a larger local record
with the retained readonly48byte prefix and references to selected inputs,
then calls457cbf0. Only raw returned HEAD QWORD exactly2 selects AL1. Other
returned heads select AL0 after a conditional allocation-release call. The
meaning, validity and effects of this late validator/formatter-like helper are
unknown; no source-level Result/enum name is invented. Earlier floating failure
paths can call a separate global diagnostic boundary before AL0. Normal ABI-
preserving returns, valid headers/payloads and stable memory are premises;
unwind, helper mutation, ownership/drop and fault behavior are not closed.

## Evidence and reproduction

```sh
python3 research/work-items/RE-004-fee-floor-policy-115/collect.py --output work/fee-floor-replay --check
python3 research/work-items/RE-004-fee-floor-policy-115/analysis.py
python3 -m unittest discover -s tests -p test_fee_floor_policy115.py -v
```

Raw scalar constants, slot relationships and selected exact instruction groups
are authenticated. Real-byte structural corruptions run below the whole-image
identity gate; they authenticate evidence, not changed native outputs. Local
branch truth tables and symbolic call plans carry no concrete helper answers
and are not execution vectors or a complete-function mathematical oracle.
No captured binary, interpreter, service, network/chain/signing/wallet runs.

New analysis uses project MIT. Collector scaffold is credited to the earlier
fee-scaling/peer-limiter packets. Original outer-fee packets, tools, captures,
imports and pins stay unchanged. This does not claim all source types/units,
software/hardware math equivalence, an owning ABI, reconstructed Rust, complete
schedule acceptance, integrated node or a gate. Next close the late457cbf0
contract and floating-environment/software path before an executable replacement.

Collection78.354s passed. Private1136B210instructions and conditional math
context1240B337instructions total2376B547instructions, all exported exactly.
26selected actual-byte instruction/data structural corruptions rejected0.804s.
Seven focused checks passed7.224s. The10call plan/2sum checks/4flag truth rows
supply no helper answers and are not native vectors. Initial collection67.843s
preceded explicit48byte readonly-prefix binding; that earlier log is retained,
not relabeled as final metadata. The collector's later docstring wording does
not change generated results; fresh replay uses the published collector.

Catalogue/check alone uses already-submitted #2655 snapshot-read fix for the
measured39.47GB repeated-read blocker. The baseline helper is restored before
actual reproduce/final audit and remains unchanged in commits; this is not an
unmodified-head local catalogue claim. All92gates/bytewindows remainunchanged.
Full repository make test/new-head hosted CI are pending; integration follows.

Integration447.402s passed: all TEN generated export/record/version files byte-exact on fresh replay80.143s;12packet-integrity checks, doctor/verify, disclosed catalogue/check overlay, baseline helper restoration and actual reproduce. Earlier7focused checks passed unchanged. Full new-head repository CI remains pending.
