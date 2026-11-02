# Node94 four-word and paired greeting-value relation: manual draft

This manual draft precedes any new aggregate checker. It is not a qualification
receipt, implementation recovery, captured execution or completed component gate.
Target: node94, 91774280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Base: 966865f1637a29ce75b019e1bf11d5529cc6f519. Coordinates are ELF VAs.

The new question is how the complete four-word decoder2558ee0 and its paired
wrapper25587d0 turn variable-width inputs into their defined result cells,
including charge, partial-consumption and error order. A32byte result does not
establish a32byte wire read. The actual greeting map2890b60 calls the paired
wrapper after a20byte key reader. Generic schema, u64 fast/slow/error grammar,
primitive byte and fixed20/fixed32 readers remain credited dependencies.

## Scope and premises

The proposed theorem covers mode QWORD exactly1, arbitrary u64 charge C and
limit L, and immutable nonwrapping valid input slices of at most isize::MAX.
State, output, input, stack and executable/data storage are separated and stable;
actual scalar/error calls preserve unrelated live state and return normally.
No source nominal type, runtime pointer value, padding validity or native ABI
is assigned. Other raw modes are retained as native context, not admitted by
this theorem. In particular the QWORD mode tests must not be silently changed
to DWORD tests in a future claim about other modes.

Primary complete FDE2558ee0..2559404 is1316bytes/332GNUrows.
Paired complete FDE25587d0..25588f3 is291bytes/77GNUrows.
The selected new aggregate denominator is1607bytes/409rows, with prior scalar
sites separately credited. Actual common scalar helper2973b90..2973c7c is
236bytes/67rows of context; full Reader466d980 and error helper466dac0 are
also dependency context. These are static records, not new recovered-byte credit.
GNU/LLVM currently partition these three retained extents identically. Data,
call/RELA and complete corruption qualification still must be closed separately.

## Four-word charge precedes every input read

At2558eee..2558ef5 the complete mode QWORD is compared to1. In this admitted
mode, the native code reads C, checks C<=MAX_U64-32, stores C+32, then tests
C+32<=L at2558ef7..2558f10. Overflow produces outer QWORD tag1 and nested
BYTE kind2 without a counter store. Exceeding L produces the same logical
error and retains the increment. Both routes consume zero bytes.

After an admitted charge, the counter is at least32 and no scalar read changes
it. The guards before words2,3,4 test counter>=8 and counter<=L when mode is
nonzero. Their panic and late-limit routes cannot occur in this admitted
mode1 domain under the stable preserving-callee premises: the initial charge
already proves both predicates and the counter is unchanged. No refund,
per-word charge, charge-by-encoded-width or second charge32 occurs inside
this four-word function. All native guard/terminal blocks remain in the raw
record; their exclusion is a domain proof, not deleted evidence.

## Four ordered unsigned values, not four raw eight-byte reads

Words1,2,3 use inlined scalar paths whose fast predicate is remaining>8.
Their fast dispatch tables are3e5984/3e5994/3e59a4, each four signed relative
entries for FB/FC/FD/FE. The final word is read by direct call2973b90 at
255937f, with the current slice and EDX0. That helper itself chooses the same
remaining>8 fast path, and otherwise uses Reader slot57745e0. Thus the fourth
word is NOT forced to the consuming slow Reader when more than8bytes remain.

All successful reads use little-endian scalar grammar: 00..FA represents its
own value; FB plus2bytes, FC plus4bytes, FD plus8bytes represent the following
unsigned value. Nonminimal encodings are admitted. Values never consume more
than9bytes, and there is no u128-success arm.

Fast FE and FF fail without advancing the slice. They reach error construction
with expected-code2 and found-code4 or12. With remaining<=8, the actual u64
Reader first consumes one available marker. FE/FF then fail with expected-code3
and found-code4/12. On empty input, kind0 needed1 consumes zero. On a truncated
FB/FC/FD extension, kind0 needed equals total_encoded_width minus the bytes
available before that read; only the marker is consumed. No available extension
payload is consumed on shortage. Every earlier successful word remains consumed.

The common helper2973b90 explicitly has its own fast dispatch at3f5d6c and the
same little-endian selector0. Status19 terminal checks in the four-word caller
are unreachable from the actual u64 Reader/error-helper result domain; no
arbitrary synthetic status is admitted as an ordinary success.

After all four words succeed,25593cd..25593e5 and255911e..2559137 write QWORD
tag0 at output0, then word1 at+8, word2 at+16, word3 at+24, word4 at+32.
The first word's low-byte/right-shift/left-shift/OR sequence reconstructs that
same full word; it does not drop its high56bits. No reorder, big-endian wire
interpretation or field-name/type inference is justified.

For every scalar failure, the caller writes QWORD tag1 at0 and forwards only
the established active nested error fields: BYTE kind at8; kind0 additionally
QWORD needed at16; kind3 additionally BYTE expected at9 and found at10. Native
wider copies also move inactive bytes; those bytes are excluded from the logical
comparison. No partially decoded word is a successful result field on error.
The successful fixed charge32 and every prior cursor advance remain visible.

## Paired wrapper and trailing raw byte

25587e3 calls the four-word function into its stack result. A first error is
forwarded without attempting the second block. First success retains its32
defined value bytes, then2558816 invokes the same four-word function again
on the updated decoder. A second error is forwarded after all first-block
consumption and counter effects. No input/counter rollback occurs.

When both blocks succeed, the wrapper charges1 for its final byte in this
mode1 domain. At2558865..2558880, old counter MAX_U64 fails before a store;
otherwise old+1 is stored before the limit test. Comparing old>=L is equivalent
to new>L after the separately checked overflow exclusion. A limit error keeps
the increment. This charge happens before checking whether the byte exists.

For an admitted final-byte charge, empty input gives nested kind0 needed1.
Nonempty input consumes exactly one raw byte and accepts all256values. There
is no boolean validation or enum-tag range check. Success writes QWORD tag0,
first block's32bytes at+8..+39, second block's32bytes at+40..+71, and the raw
byte at+72. Offsets are decimal here; native+0x48 is decimal72.

The final-byte failure join25588e3 additionally writes QWORD1 at+16 even for
kind2 budget failure. That physical write is observed and retained, but kind2
has no active logical payload; no full raw-output/padding equality is claimed.
For kind0 it is the active needed1. Earlier block errors forward their own
defined error projection, and do not acquire an invented needed1 field.

Successful paired values therefore have65logical payload bytes after the
result tag, but consume9..73wire bytes: eight independently variable-width
u64 encodings followed by one raw byte. The eight words remain in decode order.
For initial C with no overflow/limit error, final charge is C+65 with stores
C+32, C+64, C+65. Partial failures retain only actually reached charge stores.

## Actual map context, excluded from this proposed aggregate theorem

2890b60 reads a length, reserves logical96*count when its QWORD mode is nonzero,
and subtracts96 before each key/value decode. It calls fixed20reader2558e70,
then25587d0, then insertion285e420. Its loop follows original count even when
a key replaces an existing key; no accepted-length cap or duplicate rejection
follows from the96 reservation. The final normal result forwards a three-word
map header. Scalar/byte/key and collection clone ownership must remain credited.

The preliminary hypothesis that2558ee0 was a fixed raw32 reader was disproved
by its complete FDE: it decodes four variable-width values. Likewise, direct
call2973b90 does not force the final word onto the slow path. These rejected
intake hypotheses never became a model, frozen expectation or public claim.

An actual small-limit1000 map may admit at most9entry attempts after its
preceding charges, suggesting a nonfull single-leaf composition. That remains
a separate unqualified hypothesis pending complete addressed charge/constructor
and leaf-insertion proof. The3839byte1a858e0 FDE has been retained, but only
its nonfull-leaf entry and result tail were read; complete split/ancestor routes
are NOT closed. Do not claim map/lifetime/drop/allocator equivalence from this
paired-value theorem, and do not count unrelated map FDEs as newly recovered.

## Ownership and qualification still required

CanonicalRE-005-bincode-varint already owns scalar dispatch sites, including
the first inlined table in2558ee0. Canonicalstream-msg-codecs-94 owns generic
greeting/hash schema. Peer1365 owns generic scalar wrapper/cursor state;
peer1454 byte/bool leaves; peer1535 fixed20/fixed32 leaves. Peer1497's full
owned-byte proof at headc0e84d1a3a5f90af80d4433806a50674db45b1bc owns the
specialized byte-collection semantics also cloned by2891c30: unused callback,
full-QWORD payload charge, shortage preservation and bulk copy. That clone
alone is ineligible as a new contribution. Its post-allocation reload branch
adds no distinct stable ordinary-return outcome and must not be split into a
duplicate PR. No unlicensed source or another PR's implementation is copied.

The370current open-PR bodies contain no addressed2558ee0/25587d0 match, while
the canonical fast-path ownership above is explicit. This is a non-atomic
four-page inventory, not an exhaustive absence proof. Before selection or
publication recheck canonical/current peer scope. No new branch, checker,
implementation, compiler run or PR exists for this draft. Independently freeze
constructive mathematical expectations before authoring any aggregate checker;
then bind actual helper/data/RELA records, run meaningful corruption controls
and the permitted repository static checks. Never run captured instructions,
expanded captured-execution tests or networking. Leave all component gates false.
