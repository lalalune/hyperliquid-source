# Selector-0 block preimage: conditional static value contract

Target node94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; source baseline `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Addresses are ELF virtual addresses and range ends are exclusive. The 32 full FDEs in `scope.json` comprise 14,506 bytes / 3,560 native instructions. Both native partitions are retained. This is a manual proof under explicit memory/callee premises, not execution, an instruction interpreter, or an automated equivalence theorem.

## Value relation and boundaries

Let V(x) encode u64: byte x for x<251, fb||LE16 for x<65536, fc||LE32 for x<2^32, otherwise fd||LE64. U32 has only the first three cases. Let v(x) be encoded length. Concatenation below is ordered. A/H are uninterpreted20/32-byte values.

Define signature projection S(s), for a72-byte value, as
`V(LE64(s[0:8])) || ... || V(LE64(s[56:64])) || s[64]`.
Bytes65..71 do not contribute. This is a memory projection, not a claim of signature validity, canonical scalars, low-s or recovery-ID range.

Define QC projection Q(q):
`V(version) || V(start_round) || V(round) || hash32 || V(vote_count) || each(vote.signer20 || S(vote.signature))`.

Define timeout body T(t):
`signer20 || V(round) || Q(qc)`.
It has no selector tag or domain prefix. Define optional certificate C:
`00` if absent; otherwise
`01 || V(tc.round) || V(tc.vote_count) || each(S(timeout.signature) || T(timeout))`.

For block b and explicit packed time (date_i32,seconds_u32,nanoseconds_u32), the complete digest preimage is

`ASCII29("Hyperliquid Consensus Payload") || 00 || proposer20 || V(round) || V(tx_count) || each(tx_hash32) || V(Z(timestamp_seconds)) || V(nanoseconds) || Q(qc) || C(tc)`.

Z is signed zigzag: 2t for t>=0, -2t-1 otherwise. The nanoseconds encoding is U32. The outer block signature, each signature's padding, container capacities, pointer values, and packed-date low4 flag bits are absent. Ordered sequences are not sorted or deduplicated. Present-empty TC differs from absent TC. Nested timeout outer signatures are included **before** timeout bodies; using a complete selector-2 preimage for a nested row would incorrectly insert a tag and prefix.

The chosen input domain allows all three raw time words. It does not validate that ordinal/flags/nanoseconds represent a legal calendar instant. The observed converter performs no such checks. A caller wishing to impose valid-calendar constraints has a separate responsibility.

## Full block writer, sizer and loops

Writer `4776d40..4776faf` has the following ordered successful calls:

| Call site | Source/value | Callee |
| --- | --- | --- |
|4776d66|P+9c,20 bytes|4aa9e50|
|4776d8e|u64 P+88|4aa9f80|
|4776db0|u64 count P+10|4aa9f80|
|4776de9|each32-byte row from pointer P+8|4aa9ed0|
|4776e13|time P+90,12 bytes|45c4a40|
|4776e35/55/79|u64 P+30/+38/+40|4aa9f80|
|4776e9a|P+48,32 bytes|4aa9ed0|
|4776eb7|QC vector descriptor P+18|485b940|
|4776ed7|optional TC P+68|466ca20|

Every subsequent field is guarded by raw status8; the final store at4776ee2 writes success8. Failed fields propagate only the result's active payload, not a theorem that every copied inactive byte is initialized. Outer signature begins atP+b0 and no selected serializer reads it.

Sizer `4776ab0..4776d3b` measures those same fields: direct20, round and count at4776af5/6b14, raw32 rows at4776b49, time45c4b50 at4776b73, three words at4776b90/6bb5/6bd9, hash32 at4776bfa, votes485b780 at4776c17, optionalTC466cd80 at4776c37. Checked sums and the common serialized-size bound exclude its overflow diagnostic.

For tx_count=N, the writer starts at base, computes32N and advances32 per successful iteration. Zero count bypasses the pointer read/loop. The sizer uses the same stride/count. With truthful accessible nonwrapping arrays, induction gives exactlyN hashes in stored order. The same reasoning applies below to96-byte QC vote rows and184-byte timeout rows. Array-span validity is separate from serialized-length validity.

## Packed time: all raw32-bit words

Both complete bodies `45c4a40..45c4b46` and `45c4b50..45c4c56` read the same12 bytes and perform identical arithmetic before their scalar writer/sizer calls.

Let y=(date as signed32)>>13, o=(date as unsigned32>>4)&511. Thus -262144<=y<=262143 and0<=o<=511; low4 bits are never used. For y>0 set k=0,d=y-1. For y<=0 set
k=floor((1-y)/400)+1 and d=y-1+400k.
The native logical shift39 after multiplying1-y by0x51eb851f gives that quotient. Its compensation immediate0xfffdc54f is -146097. On the nonpositive branch1<=d<=400 and1<=k<=656; on the positive branch0<=d<=262142.

The resulting day number is

`day = o -146097*k + floor(1461*d/4) - floor(d/100) + floor(floor(d/100)/4) -719163`.

The second0x51eb851f sequence (high-half extraction then signed shift5 and sign correction) equals floor(d/100) here: d and its product are nonnegative. Every32-bit intermediate is within signed32 range. The certificate records the exact multiplication1461*d and cycle-compensation endpoints. No modulo-wrap interpretation is silently substituted for unbounded arithmetic.

A separate closed equation is
`day = 365*(y-1) + floor((y-1)/4) - floor((y-1)/100) + floor((y-1)/400) + o -719163`,
using mathematical floor also for negative years. Equality follows because a400-year shift changes the expression by146097 days. The arithmetic certificate checks all524,288 possible y values and the exact quotient/range identities; o enters linearly, so endpoints0/511 suffice for its range. This finite arithmetic is not target instruction evaluation.

Unsigned seconds are the high32 bits of the first input qword. The native sign-extends day, multiplies by86400, and adds that unsigned seconds word. The resulting t is within signed64 for every raw input; its exact extreme interval is retained by the certificate. Nanoseconds are copied unchanged from the third word. At45c4ae2..45c4af1, the sign test before NOT/LEA remains live through CMOVNS and selects2t versus-2t-1. The u64 writer is called at45c4afc, followed only on status8 by u32 writer4aa9ae0 at45c4b15. Sizer calls4aaa230/4aa9c90 at45c4c0c/45c4c25. This is signed-second zigzag plus nanoseconds, not clamped milliseconds or a packed-date byte dump.

This relation neither invokes nor proves the date-add constructor151f870. Concurrent PR1473 concerns that distinct helper over validated representations; its calendar context is acknowledged, but no source, tools or fixtures from it implement this packet.

## QC votes and optional TC composition

QC writer `485b940..485ba9d` emits count at485b96c, then raw signer20 at485b9b9 and S at485ba06 for each96-byte row. The temporary signature copies row+18..57 into64 contiguous bytes and passes a pointer to row+58 as the final byte. The next row is row+58+8. Padding+14..17/+59..5f is inactive. Sizer485b780 loops the same count/stride through4c7e7a0, which charges20 then4df2250's eight varint limbs and one raw byte. Full signature writer/sizer4df20d0/4df2250 are retained; all eight scalar calls and final byte/count stores are pinned.

Optional TC `466ca20..466caf4` compares0 with the first qword and branches on signed overflow. In64 bits, 0-x overflows exactly for x=0x8000000000000000: this is the absent niche on the qualified representation. Absent emits raw00. Every other first word selects present and emits01, then calls4775800 at466ca6a. Safe Option correspondence requires an actual valid Some/None native representation, not arbitrary non-niche pointer words. Sizer466cd80 increments the option size once and, when present, measures TC round at466cde5, count at466ce06, and each184-byte row via458aa60 at466ce39.

TC writer `4775800..477597d` emits round from+18 and count from+10 at477582c/477584d. With nonzero count it loads base+8, computes184N, and sets its cursor to base+b0. Each iteration copies cursor-40..cursor-1 (row+70..af), passes cursor as final-byte pointer, and calls S at47758ca. Only on success does it call timeout body4778820 at47758ee with row=cursor-b0. It advances184 and subtracts184 from its remaining count. Thus **outer timeout signature precedes timeout body** on every row. Sizer458aa60 performs4df2250 at458aab2 before4778a70 at458aac7 with the same active fields.

Timeout4778820/4778a70 serializes signer+58, round+50, QC version/start/round+18/+20/+28, hash+30, count+10 and QC vote rows through pointer+8. Its own signature+70 is not read there because the enclosing TC wrapper already emits it. This closes the graph without any call back to the block writer: TC→timeout→QC votes→signature→scalar/fixed-width leaves. No recursion through blocks or certificates is present.

## Sizing, shared dispatcher and prefix

Let s(sig)=1+sum of the eight v(limb); q(qc)=v(version)+v(start)+v(round)+32+v(N)+sum(20+s(sig)); t(timeout)=20+v(round)+q(qc). Then c(None)=1 and c(Some)=1+v(tc.round)+v(M)+sum(s(timeout.sig)+t(timeout)). Exact encoded-body size is

`D = 1+20+v(block.round)+v(tx_count)+32*tx_count+v(Z(t))+v(nanoseconds)+q(block.qc)+c(block.tc)`.

The required bound isD+29<2^63, separately from every native source span/count bound. Every partial size is nonnegative and at mostD. Consequently each overflow guard on addition remains false. The shared dispatcher45873d0 initializes the size counter1 at458740e and calls4776ab0 at4587424. Table entry0 at6f5e18 reaches this arm. It allocatesD, initializes writer length0/capacityD, and table entry0 at6f5e2c reaches4587643, which encodes the literal u32 zero at209d5c through4aa9ae0 and then calls4776d40 at4587675. All tables and the full dispatcher are retained; other enum arms are not claimed.

Induct on successful fields/array rows. A leaf appends exactly its measured1/3/5/9,20,32, or1 bytes and returns8 when sufficient capacity exists. Each subtree measures the same stable values and guards its next step on8. Starting with capacityD, no growth branch is needed; each prefix remains within allocated storage. This uses an explicit allocator/frame premise, not a proof of native ownership safety. Panic/unwind edges are retained but outside the ordinary-success relation.

Timed wrapper4b747d0 and mode wrapper471ce30 are included in full. The digest root provides mode0;471cec1..471cedf therefore directly calls45873d0 without entering the TLS mode machinery. Timing calls may observe state but are assumed to preserve all live payload/output fields and escaped aliases. The13-byte timing label at6f6078 is not a preimage field.

Concat48454d0 sums prefix length29 andD with checked allocation bound, allocatesD+29, and copies the two slices in order. The literal at6f605b is exactly the29 ASCII bytes above.

## Hash boundary and caller handoffs

Root454c050 initializes zero200-byte state, offset0, rate136, delimiter1, mode0. Full4f59a10 consumes q=floor(L/136) complete blocks by XOR into state[0:136] then calling P through slot5777790; it consumes the remaining r=L mod136 bytes and stores offsetr. Full4f59e40 copies the224-byte context, XORs01 at state[r] and80 at state[135], calls P once and copies the first32 state bytes. Requested output32<136 excludes further squeezing. Exactlyq+1 P calls occur, including whenr=0. Bounds r<136<=200 exclude panic guards under the stated valid buffers.

P=4f59480..4f59a02 is retained in full with its192-byte round-constant data. The identity of this captured permutation with Keccak-f remains conditional on the existing baseline RE-005-action-signable-94 structural identification and independently authored MIT Keccak provider. This packet proves selector0 preimage/wrapper composition, not a new formal25-lane permutation equivalence or captured digest execution. Related selector1 PR1391 and selectors2–4 PR1467 are credited background, not runtime/code dependencies.

Full signer454ad50..454aeb1 stores selector0/payload at454ad66/454ad6f, calls digest454ad81, then opaque signing14a2710 at454ad94. On its successful selected branch it copies176 bytes of body and installs65 signature bytes atoutput+b0..f0. It cannot be an oracle for the preimage by assuming the signature's meaning.

Full verifier454b700..454ba4e stores selector0/payload at454b7d6/454b7df. After preceding opaque helpers it calls digest454b81b; the following reads recover proposer bytes+9c..af and signature pointer+b0 before recovery454b96a. Its earlier pointer escapes require input/result preservation premises. These two complete caller readings establish selector/input/signature handoff and order only on traces reaching digest; they do not prove all admission gates or signature recovery.

## Necessary memory/callee premises and exclusions

All selected source values, descriptors and active fields are readable and stable across both measurement and writing. Counts are truthful; tx32*N, QC96*N and TC184*N source spans and every pointer addition are nonwrapping and within live objects, with chosen spans below2^63. The sources do not alias output/status/scratch/frames or each other in a way that changes later reads. Allocation returns fresh sufficiently large disjoint storage and cleanup preserves still-live outputs. D+29<2^63. Valid discriminants and ordinary finite entry/return paths are premises.

Opaque calls obey the x86-64 saved-register/stack contract and preserve all live source/output fields and previously escaped aliases outside their designated outputs. A syntactic lack of explicit stores does not establish this. The imported slot576dfe0 binds to memcpy, whose exact-copy/frame contract is assumed for readable/writable disjoint spans: copy exactlyn bytes, preserve source and all memory outside destination, return normally. Binding a symbol name alone is not proof of that behavior.

Error factories, allocation failures, diagnostic helpers unexpectedly returning, LSDA/unwinding, malformed pointers/counts, concurrent mutation, original ownership/lifetime soundness, native tree construction, signature validity/recovery, live network/wire envelope, proposer schedule and full authenticator integration are excluded. Native error payloads retain their active-field qualification. A safe Rust value API may choose checked length/allocation errors without assigning them captured ABI identities.

Existing SignedBlock lacks native block time. Planned integration therefore takes explicit packed time and leaves AdmissionAuthenticator and baseline types unchanged. Old block proposal/admission fixtures stub this digest; none of their invented hash/signing results is used as an expected native digest.
