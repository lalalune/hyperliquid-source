# Tier cap: selected native normal relation before new Rust

Node94 SHA2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
ELF VAs, exclusive FDE ends. Native freeze b67e8bfe569e5ca612d4b3c7424a3f5a9cabf35b1037101bd0f306da08d80ab1
was written before any new numeric oracle, expected corpus or Rust.

## Scalar entry and asymmetric arithmetic

3333580..333366e takes a holder inRDI, raw unsigned wordP inRSI and signed
wordS inRDX. No local signed-price check exists. Holder+18 is the root and+20
is the height. A null root branches333358e→3333665 and returns AL50 before
multiplication. Only the returned low byte is claimed; MOV AL does not establish
fullRAX zero-extension on this default path.

For a non-null root,3333594..333359e computes magnitude with NEG/CMOVS:
S>=0 selects originalS, S<0 selects-S, and S=i64MIN retains bitpattern2^63.
Unsigned MUL at33335a2 gives high/low words of P*magnitude. SETO at33335a5
records high!=0. The independent unsigned comparison33335b2/35b5 records
low>0x7ffffffffffffffe. OR at33335b8 combines them; MOVZX/ADD doubles the
predicate, producing numeric upper tag0 or2. These are distinct facts:
product=i64MAX-1 has tag0; product=i64MAX has tag2 without wide overflow;
P=2^63,S=2 has high1/low0 and tag2 due to wide overflow alone.

The range record has lower numeric tag2 atstack+38, upper tag0/2 at+48 and
low product at+50. Call33335df targets2fe1670. No Rust Bound layout is claimed.
The selected relation is lower-unbounded and upper-inclusive(low) for tag0,
or upper-unbounded for tag2; derivation follows.

## Full helper2fe1670..2fe1c15, selected tags only

Inputs: outputRDI, rootRSI, heightRDX, rangeRCX. The full FDE has358 byte-agreed
instructions/1445bytes. It has no ordinary external helper call; the two panic
calls are range-order/equal-exclusion paths for other bound tags. Lower tag2
skips those comparisons at2fe1697/16e4 and dispatches directly through
57acf4[2]→2fe1840 with start edgeR10=0. Upper tag0 dispatches through
57ad04[0]→2fe1854, while upper tag2 uses[2]→2fe192c.

For included upper tag0,2fe1889 compares unsignedP with ordered keys at
node+168+index*8. SETA/SBB encodes greater=1/equal=0/less=255. Greater
continues. Equality selects end edgeindex+1 at2fe18b2; less selects end
edgeindex at2fe1941/1947. Exhaustion selects node.n. Thus exact equality is
included. For upper tag2,2fe192c directly selects node.n without readingP.
The node count is u16 at+1c2. These are observed operand offsets, not a public
owned-node layout.

If start>=end,2fe194f descends the one possible child at+1c8+start*8 while
height remains positive. Height underflow here writes only front-node0 and
back-node0 at2fe1997/19a1. Other output words may be uninitialized and are not
modeled or read by the cap's empty-range path.

If start<end,2fe1971 separates the two edges. At height0,2fe19ab..19c9 writes
all six words: front node/height0/edge, back node/height0/edge. For internal
nodes,2fe1979 and2fe1bfe descend the left edge;2fe1a2e/1a50/1abe/1af3/1b0f
descend the right edge. The tables57ad14/57ad24 carry the edge states: bounded
search0/1, unbounded2 and exact-bound-consumed3. The upper state3 targets
2fe1bf5, preserving edge0 in the child after an exact parent key. Repeating
until height0 yields the first/one-past-last leaf cursors of the selected
ordered range. Selected normal lower state remains unbounded; other generic
input-bound variants are not part of the reconstructed API. All four tables'
16 destinations and full helper bytes are retained in the freeze.

Valid normal premises are a finite balanced ordered tree with stable readable
keys/values and consistent parent/child edges. The proof does not admit raw
malformed node graphs, concurrent changes or arbitrary metadata. A conditional
generic11-key height1 example can exercise internal endpoint/climb logic, but
is outside the existing validated1..3-tier MarginTable/Rust denominator.

## Cap result extraction

33335e4/35e9 read the initialized front/back node words. A null pair yieldsAL50.
When both nodes are equal,3333659 compares their edge indices and yields50 if
identical. An inconsistent non-null front/null back reaches33335fd's panic;
this is not a new safe-API error label.

For a nonempty range,333360f loads the back edge. If nonzero,333364b/364f
returns the byte at back_node+32*edge-8: value(edge-1)+24. If edge0,
333362d..3649 follows the parent pointer at+160, obtains its edge at+1c0 and
repeats until a predecessor value exists. A missing parent reaches333361e's
panic. This closes exact-bound cases where the selected predecessor is a
parent separator rather than a value in the terminal leaf. It returns the last
range entry's leverage byte, not a pointer or native Rust iterator ABI.

Thus for valid logical entries, the value is50 on an empty selected range;
otherwise the last entry whose lower key<=low-product for tag0, or the last
entry overall for tag2. The root-null case shortcuts to50.

## Existing component boundary and controls

The existing independently authored MarginTable admits1..3 sorted tiers, first
lower0 and later lower<=1e15, with decreasing leverage<=50. Some(singleton
zero-leverage table) remains meaningful here: this helper reads a byte and
performs no leverage division. OptionalNone can represent only the native
zero-root branch as a new logical safe-API choice. This does not recover raw
holder ownership, the original B-tree Rust type or full leverage admission.

For these validated bounds, changing only finite upper=i64MAX into unbounded
cannot change the final cap: both include every tier. Such threshold controls
must bind native query construction, not inflate normal-value mutant counts.
Ignoring true high-word overflow and using wrapped low0 does change the cap
on a valid multi-tier table; that is a separate normal result witness. Expected
intermediate query flags and final byte outputs will remain separate.

Credit existing RE-007-margin-path-94 for tier lookup/formulas and constructor,
and RE-004-update-leverage-path-94 for caller routing/status gates. The latter
leaves3333580 explicitly unimplemented. Only selected caller context is used:
its slot5775998 is RELATIVE3333580; source admission, other gate checks and
persistent mutation remain outside this helper reconstruction.
