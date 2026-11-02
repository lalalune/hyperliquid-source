# RE-012: first greeting response constructor and defined return relation

Manual static proof before a checker. Node94 SHA256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
91774280bytes; base966865f1637a29ce75b019e1bf11d5529cc6f519.
VAs are ELF coordinates. No target execution, register/instruction evaluator,
symbolic execution, network, original Rust ABI or full schema is claimed.

## Question, credit, and premises

Which constructor/limit does the actual first configured connection use for
its reply, which defined response fields survive the wrapper, and how are
those fields paired with its retained stream? The selected byte cases cover
response selectors1..5, invalid scalar headers and truncations. Selector0's
vector/hash decode remains outside the byte model. The outer conditional
envelope also admits a separately supplied normal decoder result/mask, without
inventing the opaque selector0 helpers' behavior.

Credit canonical transport-tcp-frame-read-94/lz4-frame-94 for frame admission
and read/decompression, stream-msg-codecs-94 for the related greeting schema,
and RE-005-bincode-varint/slow-widths for primitives. Open1365 owns scalar
wrapper charging/cursor/error relations and the different438b5c0 request;
1454 owns byte/bool leaves;1357 owns write-first timeout. None is reclaimed.
Author1672/1685/1697/1706 retain address/readiness/stream/send-request results.

Premises: fresh parent2037ac0 with its ordinary successful stream, stable
disjoint initialized active fields, valid nonwrapping input slices and no
reentry/concurrent alias mutation. Admit the already mapped reader's normal
response descriptor and ordinary preserving allocation/copy/free, clock,
diagnostic/TLS helper contracts. Selected normal TLS brackets restore their
state; invalid/destructed TLS and exceptional routes are excluded. No compiler
or live object/state is fabricated. Only active written fields form output;
copies of inactive/uninitialized payload/padding are not semantic values.

## Actual shared constructor values

At20382b2, A is the raw byte at parent+1f0, retained from original+201.
20382bb/20382c0/20382c5 select L=1000 for A==0, otherwise3000000000.
The separate original+203 byte retained at+1f8 is not A. L is saved at+468,
copied at2038324 to+470 and at203835b to reader argument+20 (parent+228).
This supplies the actual max-frame-length argument; canonical reader admission
already establishes equality is allowed. Do not equate compressed frame
length with decompressed response length or logical decode charge.

The read result at203837a supplies capacity C, pointer P and length N from
stack+b0/+b8/+c0. MIN+1 takes the pending path2038841; MIN takes read-error
handling and bypasses decoding. For an admitted normal descriptor,20384a9
reloads L from+470,20384b0 loads A from+488, and20384b8/c6 set the diagnostic
arguments;20384d8 calls28bdc00(P,N,L,A). A controls a TLS/diagnostic path,
not an inferred original source boolean/type or a recovered peer role.

28bdc00 retains P inR15,N inR12,L inR14,A inEBP. Every selected normal
constructor sets mode DWORD1, limitL, inputP/N and chargeQWORD0 at stack
+28/+30/+38/+40/+48, before25618f0. The three call sites are28bddc0,
28bde6b and28be25d. Their setups are at28bdd92,28bde3d and28be22f.
The latter two are TLS alternatives, not different input/limit modes. The
preserving-helper premises keep these exact inputs equal on all three paths.

## Selected simple response bytes, with primitive credit

25618f0 charges4 before reading the u32 discriminant through2973aa0 in
little endian. Its dispatch table3e5aa4 maps0→2561970,1→2561a1e,
2→2561a06,3→2561a12,4→25619fa,5→2561a69. Above5 returns outertag8,
active error kind5, offendingu32 at+0c, type label3e63d4/length18 at+10/+18
and range metadata203580 at+20. That label reads AbciStreamGreeting;
the selected range record is16bytes, not the adjacent string bytes after it.

Selectors2..5 write only their result tag (selector+2) as a QWORD at+0.
They perform no later scalar read. Their logical charge is4, while the
discriminant can consume1,3or5bytes. Nonminimal FB/FC encodings are accepted
by the credited primitive. A nonempty suffix is not itself a decode failure.

Selector1 charges8 before the inline first u64, then calls2558c90 twice,
stopping at each earlier error. On three successes2561bca..2561bd9 write
QWORDtag3 at+0, SECOND value at+8, THIRD at+10 and FIRST at+18. Charge is28,
independent of their actual1/3/5/9byte widths. L is always at least1000 for
this actual constructor, so a selected scalar-only reply cannot fail its
logical4/28charge boundary. Do not manufacture a different caller limit to
claim a fresh scalar-budget transition; that transition remains1365's work.

For selected scalar failures, preserve only active fields: kind0 has its
needed count, kind3 its expected/found bytes, and outertag8. Truncated extended
Reader inputs consume the marker only; fast rejected markers remain unread.
Header/u32 rejected FD/FE/FF expected code is2; u64 expected code is3 on
Reader paths and2 on fast paths. These primitive effects are credited context
for the actual outer failure/diagnostic relation, not new Reader recovery.
No active-field comparison may include copied but unwritten temporary cells.
The active error projection is QWORDoutertag8 at+0, BYTEkind at+8;
kind0's QWORDneeded at+10; kind3's BYTEexpected/found at+9/+a; kind5's
DWORDoffending at+c, type reference at+10, QWORDlength18 at+18 and range
reference at+20 (hex offsets). Image references are symbolic image+VA tokens,
not fixed runtime pointer values or an invented loader/ASLR contract.

## Wrapper consumption and result projection

Each decoder output's first word is tested against8 at28bdde7,28bde92,
28be284. Error8 sets the diagnostic consumed word to0 without inspecting the
remaining length (28bde0b..12,28bdeb6..bb,28be2a4..385). Thus a scalar error
can have consumed an input marker while this wrapper reports consumed0.

For a non8 result,28bdf3c,28be009 or28be323 subtract the decoder's remaining
length R from entryN. R>N takes a diagnostic/panic edge; that is outside
ordinary return. Otherwise the diagnostic count isN-R. There is no requirement
that R==0. This is a wrapper observation, not a network delivery guarantee.
The three routes join28be073 after their admitted TLS restoration. Clock/
optional log calls preserve the saved result.28be12e..28be18a copy the120byte
window to caller output. The defined active cells are unchanged, and no
consumption/timing fields are appended to that window. Original120byte
layout, inactive contents, padding and allocator/ownership identity remain
outside the safe logical relation.

## Parent disposition and retained stream

After the wrapper returns, capacity C>0 causes the recorded release request
(P,C,0) at2038592..203859a; C==0 skips it. This is a raw helper request,
not a claim about actual allocator ABI or a free implementation. The input
buffer is released before the outer selected result is returned, including
the error8 route. On an exceptional wrapper path, no normal cleanup claim is
made.204b040 maps decoder error8 through an opaque error-conversion boundary;
the caller selects its existing error/backoff route instead of a normal result.

For a normal non8 response,203867c goes2038973. Its active response cells
are retained through the existing diagnostic path.2038bb0 checks the stream
tag T against2; T2 does not reach the selected ordinary return. With the
admitted successful T0 stream,2038bb0..2038c40 copy response offsets0..77 to
outer offsets0..77, put T at outer+78, and copy stream offsets8..97 to
outer+80..10f (hex coordinates). Therefore each supplied defined stream-tail
cell at offset s in[8,152) maps to outer offset s+120; the stream tag maps
to120. The scalar-only response tag/fields retain their offsets. Known stream
padding remains excluded, as in1697. This does not validate every original
enum bit pattern or initialize any hole merely because a wide copy occurred.

## Freeze plan and remaining validation

Freeze independently constructed inputs/expectations BEFORE an aggregate
checker: all raw A constructor choices; admitted decoder-result/mask envelope
representatives including error consumed0 and non8 underflow; actual unit,
nonminimal-header and three-u64 replies with suffixes; selected scalar header/
truncation failures. Build byte cases from known encoded values and lengths,
not a captured instruction/register interpreter. Distinguish decoded field
order, logical charge, actual consumed bytes, wrapper diagnostic consumption,
result-defined cells, release requests and retained stream placement.

Do not count an artificial selector0 scope marker as a target match. Selector0
byte parsing, vector/hash allocations, original source types/ABI, actual
reader polling/error conversion, I/O, expiry/retry/liveness, TLS fairness,
unwind and full connection acceptance remain unclosed. Wrong aggregate rules
must exercise the NEW constructor/suffix/diagnostic/return relation; primitive
scalar controls and schema findings remain credited context.

Eight complete FDEs currently retain10346bytes/2049GNUrows including credited
dependency context. Bind FDE/CIE, all selected call/RELA/table/literal identities,
retain full GNU/LLVM raw exports and account only for adjacent standalone LOCK
prefix splits without omitting or masking bytes. Static corruption controls,
normal/-O receipts, unchanged Linux expectation replay and root allowed checks
must pass before a PR. Fullmake test contains unauthorized captured-instruction
evaluators and is NOT RUN. No host CI/compiler/Rust build, target execution,
full schema/nativeABI/transport equivalence, complete gate or new byte credit.
