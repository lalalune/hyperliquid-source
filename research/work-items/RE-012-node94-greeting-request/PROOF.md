# RE-012: fresh post-connect greeting byte request, manual proof before checker

Base966865f1637a29ce75b019e1bf11d5529cc6f519. Node94 is91774280bytes,
SHA2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Coordinates below are ELF VAs. This is a manual static argument, not execution,
an instruction interpreter, symbolic executor or original Rust ABI recovery.

Question: after the first successful configured IPv4 connection, which bytes
does caller2037ac0 actually supply to its greeting frame writer? The diagnostic
literal abci_stream send tcp greeting at3c4343 is29bytes; its length does not
establish a29byte payload. General compression/framing/timeouts are already
owned by transport-tcp-frame-write-94, and the output stores of28c0b90 by
RE-001-string-result-wrappers-94. Credit both fully. The new boundary is the
serializer's complete size/write pair and the actual caller-to-writer value
flow. No general frame writer, wrapper or logical message schema is reclaimed.

Premises: enter the fresh caller path, complete the previously established
ordinary successful connection, retain stable nonaliasing parent storage and
the selected valid stream, and admit ordinary preserving clock, allocation,
copy, growth and deallocation contracts. The target is never run. TLS/runtime
state, scheduling, socket writes, error/unwind/lifetime and elapsed behavior
remain outside the relation. Synthetic raw byte values are projections; no
claim that every such bit pattern is a reachable valid original Rust value.

1. At2037b70..2037b77 the original parent WORD at+201 is copied to+1f0.
   Denote its two little-address-order bytes A and B. Config bytes at+1f2..
   and the later stream are separate. At203808f RSI becomes parent+1f0.
   Parent+208/+210 receive the diagnostic pointer3c4343 and length29;
   parent+528 retains the source pointer. R8=29 is diagnostic context.
   EAX=0 at20380d3; EDX=AL at20380dc. At20380df28c0b90 receives
   output parent+508, source parent+1f0 and EDX0. Resume arms are not selected.

2. In28c0b90, input EDX is retained in EBP. The initial admitted clock call
   precedes testEBP; with0,28c0bbb directly jumps28c0d34, avoiding the TLS
   bracket arms.28c0d3c calls28c14f0 with the same source and stack+40 output.
   Later admitted elapsed-time calculation preserves the produced object.
   BPL0 skips the optional log. Tag8 at28c0d8e selects the existing credited
   copy of three words from stack+48/+50/+58 to output+0/+8/+10.

3.28c14f0 zeroes size-state words stack+38 and+48.25599e0 receives a reference
   to the source pointer and this state. It reads size atstate+10, initially0.
   For abstract starting count C, the first check refuses maxU64. Otherwise
   it stores C+1 and checks that against maxU64, stores C+2 and checks that,
   then stores C+3 and returns tag8. Thus normal counts are0..maxU64-3;
   C=maxU64-2,-1,maxU64 take a panic edge at the appropriate check.
   Here C=0 gives3. The compare of source byte+1 at25599f6 has its flags
   overwritten by the immediately following count comparison; it does not
   branch on, normalize, validate or change that byte in this relation.

4.28c14f0 observes tag8 and positive count3, requests an allocation of3 via
   slot576dfd8, and initializes its output vector header capacity3,pointerP,
   length0 at stack+20/+28/+30. It initializes the writer-state wordstack+10
   to0 and calls2559a40 at28c15a8. The allocation/error helpers remain
   admitted contracts; no actual heap object or ownership type is invented.

5.2559a40 reads source byte0 into BPL, stores it atP+length, increments length;
   reads source byte1 into BL, stores it at the next index and increments;
   then stores literal0 at the next index and increments. Each preceding
   equality capacity==length branch can call251b070 to grow the vector.
   With capacity3 and initial length0, all three tests are unequal and no
   grow call is needed. Its exact bytes are [A,B,0], length3, result tag8.
   There is no boolean coercion, enum-sized prefix or diagnostic string copy.
  28c15b9..28c15c8 returns tag8 followed by(capacity3,P,length3).
   Through the credited wrapper stores, parent+508=3,+510=P,+518=3.

6.20380e4 loads parent+510/+518, then203810e places these words in writer
   argument+18/+20, where argument starts parent+218. Argument+0=0,+8 has
   f64bits404e000000000000(60),+10 is the retained stream.204b340 reads
   pointerP and length3 at204b382/386.3<1025 takes204b4f5 raw path; positive
   length allocates3, memcpy at204b6e0 copies the same three bytes and clears
   compression flag. The already credited frame construction rejects lengths
   with nonzero upper32bits;3 passes.204b73f swaps the low32bits, stores
   length3 big endian, writes flag0 atframe+4 and appends the raw3bytes.
   Hence the frame REQUEST buffer is exactly0000000300 A B 00 (8bytes).
   This is a constructed buffer, not proof any bytes reached the socket.
   The previously owned chunk/default-timeout result is context: argument
   flag0 selects20.0 despite the carried60.0. Do not re-credit that result.

7. Caller2038133 distinguishes a pending writer result using ALbit0; only
   after the completed result does2038141 drop the writer then2038146..5b
   deallocate the retained serialization buffer when its capacity is nonzero.
   This packet does not close writer polling, actual pending/error tags,
   retries, timer expiry, registration ownership, unwind or general cleanup.
  2049950 and204b040 remain provisional later-response context, excluded from
   the proposed greeting serializer relation.

Before defining a checker, freeze all65536 raw(A,B) projections independently:
original offsets513/514, retained offsets496/497, size3, one allocation request3,
three stores[A,B,0], logical vector header(cap3,len3), writer length3/rawflag0,
and exactly8 frame-request bytes. Also freeze size-counter boundaries and
ordinary small counts independently of instruction/register simulation.
The checker must use a separately authored aggregate specification and reject
wrong field order, boolean normalization, diagnostic payload, omitted zero,
nonzero suffix, wrong width/header/flag and stored60-default mistakes.

Six complete FDEs are intended as identity/context, not a semantic coverage
denominator:2037ac0,28c0b90,28c14f0,25599e0,2559a40,204b340.
Full FDE/CIE, GNU/LLVM partitions, selected RELA/direct transfers and data still
need a qualified packet. Keep raw exports, account for adjacent LLVM LOCK
prefix splits without omitting bytes, and use no masks. Freeze normal/-O
expectations before the aggregate checker; replay unchanged on Linux, apply
below-image corruption controls and run actual root allowed checks before PR.
Fullmake test contains unauthorized captured-instruction evaluators and is not
run. No target execution, network, compiler/nativeABI, Rust implementation,
complete gate, accepted work, whole-transport or new recovered-byte credit.
