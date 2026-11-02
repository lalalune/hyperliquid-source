# Outer configuration acceptance relation, conditional manual argument

Target: visor SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
This independently authored argument supplements own1516, using credited
own1590 scanner, strict decoded-string, recognized-name visitor and diagnostic
arguments. The new leaf observations and dispatch-table audits are in the
00:57 intake. No captured execution, instruction interpreter, symbolic execution,
Rust implementation or recovered-byte count is implied.

## Exact boundary and premises

The proposed claim concerns the normal success code/error-tag acceptance of
wrapper `4aa3b0..4aa4be` over a **valid UTF8** byte slice. The surrounding file
envelope is credited to1607. The wrapper initializes scratch cap0/ptr1/len0 and
depth flag0/budget128 at `4aa3d2..4aa3ed`, then calls `4ab790` at `4aa3f9`.
No arbitrary incoming budget is assumed. A successful missing-field default
call at slot7e6d50 is an admitted producer of one code D in0..78. Its actual
path/read/trim/name behavior and possible nonreturn are1516/1550 context; this
claim does not predict D, its effects or a result when it does not return.

Assume valid stable nonaliasing input/frame/storage, length<2^63, and normal
prefix-preserving allocator/reallocator/copy contracts. Normal diagnostic
constructors have the retained1590 result origins. Cleanup may have indirect
destructor effects: admit valid diagnostic payloads and normally returning
cleanup/destructor/free operations preserving the still-live parser frame and
selected error payload. This does not claim heap/unwind/OOM/allocator closure.

Only success/error tag and successful code, plus whether default is reached,
are proposed. Exact error bytes, messages, failing cursor, error-side allocation
effects and all error precedence are excluded. The raw caller does manipulate
and preserve earlier error payloads as described below; that is distinct from
a complete error object or ABI theorem.

## Language relation

Let W be any string over bytes9,10,13,32. Let S be the credited strict JSON
decoded-string language: ordinary valid UTF8 excluding raw control bytes,
quote and backslash; eight simple escapes; u escapes with paired surrogates
required. Let I be a discarded string: the same ordinary-byte and simple-escape
syntax, but each u escape requires **exactly four ASCII hex digits** and does
not impose surrogate pairing. Both consume their closing quote.

Let N be `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`, without converting
its mathematical magnitude to an integer or float. The ignored-value language U
is the least finite grammar containing I, N, true, false, null, arrays of U and
objects with I keys and U values, separated by W/comma/colon in the usual
positions. Empty arrays/objects are included. No trailing comma is included.
Duplicate I keys are allowed and have no decoded-key lookup. These are syntax
relations; scalar prefixes require the enclosing delimiter to complete a value.

Let V be the credited1590 one-value name relation: a strict S string decoding
to exactly one recognized name, or an object containing exactly one strict S
recognized-name key with null value. It yields the corresponding code0..78.

The outer value is either:

* An object with zero or more S keys. Every decoded key equal to exactly
  aws_name must have a V value, and there is at most one such key. Every other
  key has a U value. A recognized field supplies its V code; absence supplies D.
* An array containing either zero elements (code D), or exactly one V element
  (its code). It does not contain arbitrary U elements or a second value.

The wrapper accepts precisely W + outer value + W with end-of-input, subject to
the normal-return premises and admitted default. This is not a general JSON
decoder, and a valid JSON scalar at the top level is not an outer value.

## Object and key induction

`4ab7c2` supplies mask100002600; the byte guard and bit tests identify exactly
W. `4ab80c..4ab818` selects only `[` and `{`; other bytes use a type diagnostic.
The object consumes `{` at `4ab847` and starts with first=true and marker4f
at `4ab854..4ab857`. At the loop head `4ab860`, the invariant is:
the consumed prefix contains the opening and a complete comma-delimited field
prefix; marker4f means no successful known field, otherwise marker is its code;
the current cursor precedes W and the next delimiter/key.

`4ab890` accepts `}` before requiring a new field. For a first field,
`4ab899..4ab8a5` requires quote. After a field, `4ab8aa..4ab8f7` requires comma,
W and then quote; `}` after comma is a specific diagnostic. The key consumes
its opening quote and clears scratch length at `4ab907..4ab90e`, then calls
strict decoder7e6050->64f440 at `4ab921`. Error tag2 exits; otherwise the exact
length8 and literal word656d616e5f737761 comparison selects aws_name. Escaped
spellings are compared after decoding. Surrogate rejection for S is1590's
credited Unicode argument, not inferred from a generic JSON library.

Known keys require marker4f at `4abe98`; duplicate recognized keys therefore
fail before another value is considered. `4abee8..4abefb` consumes the required
colon after W; `4abf07` calls V. Its successful code0..78 cannot equal sentinel4f.
Unknown keys require the same colon at `4ab9b1` then clear scratch length and
run U. Both successful paths join `4abf26`, set first=false and restore the
object-loop invariant. Only normal successful branches reach the closing
object corridor `4ac010`; missing marker invokes default before closing is
consumed. This timing is already1516 and remains credited.

## Ignored-value pushdown induction

At `4ab9e0`, lookahead is current cursor+2. The read at lookahead-2 selects the
current token. W advances the stored cursor one byte. Quote and minus consume
one byte (`4abc14`, `4aba30`); digits do not. The retained table88050 chooses
only `[`, `{`, f, n, t within91..123, with other dispatch bytes reaching the
digit/error guard. Literal paths compare every remaining byte of true/false/null.
The numeric helper's grammar and lack of conversion follow the00:57 manual
argument; at least one required integer/fraction/exponent digit is checked.
64f6b0 handles I, including independent valid four-hex units of all65536 values.
Its tablebbac0 and return-to-scanner edge bypass the strict surrogate assembler.

For nested containers, maintain a finite stack of ancestor opening delimiters,
a current delimiter and a completed-element flag. At `4aba6f..4abaa6`, opening
`[` or `{` pushes the old current delimiter iff already inside a container;
otherwise it starts the first current delimiter with no ancestor. Scratch
length counts the saved ancestors; growth4ad140/4ad0c0 preserves them under the
stated allocation contract. The opening is consumed and the flag is cleared
at `4abcd0..4abce9`.

`4abd10..4abd52` skips W and permits only a matching close. A close consumes
itself. Empty ancestor stack means U is complete (`4abf22`); otherwise pop the
last delimiter and mark the completed child at `4abd6c..4abd7d`. This establishes
both empty-container admission and correct close matching. A nonclose token
requires a new element when the flag is clear. When the flag is set, the only
continuation is comma; it is consumed by `4abda0..4abdb3` and another element is
required without revisiting the empty-close check. Thus trailing commas fail.
For arrays the required element returns to token dispatch `4ab9d4`. For objects,
`4abdb7..4abe84` requires an I quoted key, W and colon, then enters that same
value dispatch. It performs no decoded key or duplicate lookup.

After a scalar succeeds at `4abc4f`, an existing current delimiter continues
the same close/comma corridor. A scalar with no current delimiter completes U;
the outer parser subsequently checks its separator. The stack alphabet is only
`[`/`{`, every push corresponds to a consumed opening and every pop to a consumed
matching close. Induction over finite U syntax gives acceptance and cursor after
the full value; conversely every successful dispatch/close corridor builds one
U production. Rejection of mismatched closes, missing colon/comma, absent
value, malformed literal/string/number follows the distinct diagnostic edges.

## Sequence, depth, closing and result tags

`4abf65..4abf90` consumes `[`. After W, immediate `]` invokes default at4ac001;
otherwise4ac039 calls V once. Normal-return result and payload are retained in
BPL/R12 or R8D. The continuation accepts only W then `]` at `4ac2a2..4ac2b4`.
A comma explicitly leads to error regardless of the following token, so there
is no second value and no trailing comma. A successful code is stored at out+1
at4ac301 and tag0 at4ac304/4ac306; diagnostic corridors store payload at out+8
and tag1 at4ac218..4ac21e. `4ac640` provides the credited position/error wrapper.

The wrapper's budget128 permits the outer decrement and at most one V-object
decrement, leaving at least126. Each ordinary return restores its own admitted
decrement (`4ac064` for sequence, `4ac17c` for object; credited1590 for V).
The ignored pushdown path does not read or write state+49; its nesting consumes
scratch capacity rather than this budget. This does not prove unbounded actual
resources. Arbitrary caller budgets0/1/2 and their error-side restoration are
outside the wrapper-initialized claim and must not be generalized from it.

Object error joins restore R15 as the input triple pointer (`4abf52` or4ac171)
before final close checks. If a selected diagnostic already exists, a secondary
closing diagnostic is cleaned and the earlier selected diagnostic retained
(`4ac0e3`, `4ac1f5`, `4ac20d`). Cleanup4ab2a0 may use a vtable destructor, and
4ab250 is also used on unwind landings; their normal contracts and unwind
exclusion above remain explicit. No success path emerges from an error BPL1.

Finally `4aa3fe` skips suffix processing on an error. On tag0 it skips only W
at `4aa430..4aa454`; a remaining byte creates an error at4aa47a. Scratch storage
is released on ordinary return. This completes the proposed wrapper acceptance
relation while keeping error cursor/payload effects and allocation internals
outside the claim.

## Qualification still required

This draft is not yet publication evidence: integrate full retained ranges,
data and call/relocation bindings; freeze independent expectations before
creating a proposed parser model; check corruption controls and ordinary/-O
receipt equality; run applicable authorized root checks. Recheck current base,
ownership and existing1516 head before a substantive amendment. No component
gate can advance from this bounded relation.

# Boundary clarification for the provisional outer relation

The original addressed draft and frozen files remain byte-preserved. The
proposed full-input relation additionally requires the input-triple cursor to
start at0. Wrapper4aa3b0 copies caller fields rather than independently resetting
that input cursor. Its locally initialized scratch storage and depth128 are
separate from this admitted caller input. No arbitrary nonzero-cursor claim is
made. All synthetic inputs in the frozen constructions and abstract parser use
cursor0.

The first frozen expectations mistyped NvTestnet0x21 as decimal21 in the two
all-u16 categories. The credited79-name table supplies decimal33. The original
failure is retained in visor-outer-expectation-correction-20261102T011254Z.json;
the corrected v2 corpus is an explicit post-model fixture correction, with
unchanged parser logic and altered read paths only. Do not describe v2 as
frozen before that parser existed. The initial v1 source/corpus/receipt,
pre-provenance-correction v2 receipt and ordinary/-O successful v2 receipts are
all retained. No captured runtime result is inferred from any of them.

The provisional48-FDE source recipe includes the39FDE credited1590 context,
three credited1516 outer/wrapper/callback bodies and six new dependency bodies.
It binds86selectedRELA records,138direct transfers and18data extents. This is
static identity intake. The13remaining LEA targets include the retained callback
entry4acb70 and opaque numeric/format/position metadata. Their values/effects
must stay explicit premises; neither the recipe nor abstract grammar agreement
constitutes a complete native or error/allocator closure qualification.

# Provisional outer-configuration relation: manual research notes

This is an unqualified working draft, not a submitted packet or implementation.
Target SHA-256: `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
Addresses are original image VAs. No captured execution, CPU/register/branch
interpreter, symbolic executor, Rust build, gate change or recovered-byte credit.

## Attribution and question

Own draft1516 already retains the entire `4ab790..4ac58f` body, but proves
selected `aws_name` marker and fallback timing only. Its selected anchors must
not be republished as an independent contribution. Own1590 supplies the
recognized-name value visitor `4a7cf0`, strict decoded-key/string dependency,
normal diagnostic origins and hex/scanner lemmas. Own1550 supplies raw names;
own1607 supplies the conditional file-read envelope. These are credited context.

The additional question is the complete conditional outer object/sequence
relation, especially ignored unknown values. Prefer a substantive amendment to
1516 if the relation can be closed; a new small anchor-only packet is not justified.
No branch or public mutation has been made for this question.

Premises: valid stable nonaliasing frames and slice storage, cursor in bounds,
length below2^63, admitted depth state, normal error constructors and normal
prefix-preserving allocation/reallocation/copy/cleanup contracts. The current
argument does not prove unwind, OOM behavior, heap safety or a source-language ABI.

## Ignored string helper is distinct from decoded string helper

The outer body calls slot `7e6058` at `4abc29` for a discarded string value and
at `4abe1b` for keys inside a discarded object. Its single RELATIVE relocation
binds `64f6b0`, not decoded string `64f440` (slot `7e6050`). The complete FDE
`64f6b0..64f7eb` has315bytes/86rows with identical GNU/LLVM raw partitions.

At entry and `64f6f0`, the credited scanner `64f0d0` skips ordinary bytes to
the first byte below32, quote, backslash or end. Scanner does not validate UTF8;
the complete configuration reader's admitted UTF8 envelope is separate context.
End routes to the normal diagnostic constructor. A quote at `64f797..64f7a3`
advances the cursor past it and returns zero. Any other non-backslash special
byte routes through error16 at `64f7c2`. A backslash consumes the next byte and
dispatches through the84 signed32 entries at `bbac0`, after unsigned range
normalization by34 (`64f738..64f74a`).

The retained table has precisely these destinations:

* quote, slash, backslash, b, f, n, r, t -> `64f6f0`, continuing the scan;
* u -> `64f74c`, calling credited four-hex helper `64f7f0`;
* the remaining75 in-table byte values -> `64f78d`, error12.

The172 out-of-table byte values also reach error12. Thus247 of256 possible
post-backslash bytes reject. The absent-byte branch through `64ef70` has its
normal diagnostic origin covered by1590, without claiming exceptional behavior.

At `64f757`, the helper inspects only the returned word tag. A successful hex
unit is ignored and execution continues at `64f6f0`; no surrogate guard, UTF8
encoding or second-unit requirement follows. In contrast, decoded string
`64ebe0` in1590 rejects low surrogates and requires a matching low unit after a
high unit. Conditional inference: ignored strings admit syntactically valid
`\uXXXX` units d800..dfff individually. This is a lexical skip distinction,
not an established vulnerability or a claim that the overall reader admits
ill-formed raw UTF8. Examples to freeze only after the full relation is closed:
`{"unknown":"\uD800","aws_name":"NvTestnet"}` versus an outer key
`{"\uD800":0,"aws_name":"NvTestnet"}`; the latter key goes through the
strict decoded-string path and rejects under the credited1590 relation.

## Ignored numeric lexical helper

`4aaa10..4aac5a` is586bytes/158rows, GNU/LLVM raw partitions identical.
At `4ab9e0..4aba41`, the dispatch lookahead is cursor+2, so its source byte
load at lookahead-2 is the current byte. The minus corridor stores lookahead-1,
consuming precisely the minus before calling the helper. Digits enter without
that step. The quoted-string corridor similarly consumes its opening quote
at `4abc14..4abc29` before calling64f6b0.
The helper consumes a required digit and separates0 from1..9 at `4aaa34..60`.
A digit immediately after leading0 routes to error13 at `4aaa47`. Nonzero
integers scan digits at `4aaa70..89`. Fraction paths require at least one digit
after a dot (`4aaab8..4aaad3`); exponent paths require at least one digit after
optional plus/minus (`4aab47..4aab95`, and the fraction exponent corridor
`4aab17..4aab42`, `4aabe1..4aac39`). Remaining digit loops advance to the
first nondigit. The normal success return clears EAX (`4aac3e`) or reaches
`4aaa8b` with the loop's zero EAX. The only calls construct errors through
credited `4aa4c0`/`4ab200`.

Provisional successful prefix language:
`-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`.
This is a lexical relation: no numeric accumulator, finite-float check or
integer overflow conversion is performed by this helper. Enclosing object or
container separators still reject a remaining invalid suffix. For example a
very long exponent can pass this skip grammar without claiming that the
recognized-name value visitor accepts numbers. Cursor behavior on malformed
inputs is not yet completely specified and must not be inferred from regex.

## Ignored arrays/objects use an explicit delimiter stack

The signed33-entry table `88050` handles bytes91..123. Only `[`, `{`, f, n,
t have special destinations; others go to the digit/invalid dispatch. Before
discarding an unknown field, scratch length `state+10` is cleared at `4ab9b5`.
An opening container uses `4aba6f`; when already within a container its prior
delimiter is pushed to scratch storage. The new delimiter is held in R15B.
`4abcd0..4abceb` consumes the opening and sets the no-element flag.

At `4abd10..4abd85`, whitespace is skipped; `]` closes only `[`, and `}` only
`{`. A matching close consumes itself and either returns to the outer object
at `4abf22` when the stack is empty or pops the parent delimiter and marks a
completed child. A completed scalar at `4abc4f..4abcaa` joins the same
container-continuation corridor, or finishes an unknown top-level scalar.

After an element, a comma is required before another. After a container opens,
a matching close is allowed immediately. `4abdb7` separates array value parsing
from object quoted-key parsing. A discarded object's key calls64f6b0, then
requires a colon at `4abe80`. Unknown nested keys are not decoded or matched to
aws_name. A comma followed by a matching close goes through a required new
value/key path and rejects rather than taking the empty-container corridor.
Literal f/n/t matching checks the remaining false/null/true bytes directly.
No independent duplicate-key set is maintained for discarded objects.

The push helper `4ad140..4ad1af` checks length+additional carry and chooses
capacity at least8, at least twice previous capacity and at least required size
subject to its explicit arithmetic guards. `4ad0c0..4ad138` frames allocator or
reallocator success/failure. A normal successful growth updates capacity and
pointer while retaining scratch length. Prefix preservation is an explicit
allocator contract, not a recovered allocator theorem. Cleanup helpers
`4ab250..4ab29e` and `4ab2a0..4ab392` are retained; complete payload/layout
arguments and the exact admitted cleanup contract remain to be integrated.

## Outer relation and remaining obligations

The outer key path decodes and compares exactly eight decoded bytes aws_name.
A recognized value code0..78 from1590 makes sentinel4f distinguishable from all
valid values. Duplicate recognized fields reject before the next colon.
Unknown fields follow the skip grammar above. Missing recognized field invokes
default before the closing delimiter is validated/consumed, as already1516.
The array form supplies zero or one recognized-name value; empty invokes
default, extra values/trailing comma reject. Wrapper4aa3b0 requires only four
whitespace bytes then end after successful outer parsing.

Outstanding before qualification/publication:

1. Complete an addressed invariant for all unknown-container push/pop paths,
   scalar/closing precedence, outer depth admission/restore and error framing.
2. Bind all full ranges, data and diagnostic dependencies in a reproducible
   packet with nonneutral below-identity corruption controls. The new intake's
   six FDEs1452bytes417rows and two tables468bytes are retained observations,
   not a semantic proof denominator or new recovered-byte count.
3. Freeze independently justified lexical and composed expectations before
   creating a proposed relation model. Do not use Python JSON as an unqualified
   oracle for strict-key versus discarded-value Unicode handling.
4. Recheck live ownership and decide the1516 amendment scope. No implementation,
   root validation, actual compiler invocation or full make test occurred in
   this intake. Existing prior checks remain historical.
