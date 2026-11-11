# Borrowed logical header writer — proposed host contract

This is a pre-source design, not an implementation or test result. It specializes the conditional native relation in ../SOURCE-SCOPE.md; the raw capture and full eight-body proof remain unchanged. No hash/feed source, physical bucket API, injected lookup answer, network request or native ABI is exposed.

## Inputs and result

A dependency-free `no_std`, no-allocation, safe Rust library is proposed. `Name` is either `Builtin(u8)` or `Custom(&[u8])`. `Group` borrows one name and a slice of byte-slice values. The single writer accepts ordered primary groups, spelling groups, a Boolean capitalization choice, a caller-owned mutable output byte slice, and its initial used length. It returns the new used length or one of the ordered host errors below. This description does not require a separately constructible map object or a new transport driver. The Boolean corresponds to the native ECX low byte being zero/nonzero; high bits are ignored, and no raw-register ABI is exposed.

Builtin0..80 maps to the exact81-entry table in BUILTIN-NAMES.json. A custom byte string is arbitrary, including empty, non-ASCII, zero, colon, CR and LF. No HTTP grammar validation is inferred. Equality is tagged: builtins compare ordinals; customs compare exact length/bytes; cross-variant equality is false. Case is significant. Each map has at most65535 groups and unique tagged names, but values may repeat and different tagged names may render identically. Every group has at least one value occurrence; an empty byte string is an occurrence, not absence.

Source names, values and group arrays are immutable valid Rust borrows. They may share immutable storage with each other. Safe exclusive borrowing excludes aliases with the writable output. Native valid/nonwrapping memory, initial output used<=capacity<=isize::MAX, ordinary helper frames, exact copying/equality and successful allocation behavior are additional correspondence premises; the source receives no raw native addresses and does not validate them.

## Exact validation and refusal order

Validation is eager and finishes before any output write. The following are **global passes**, not a per-group mixture. Within a pass, primary precedes spelling, and indices increase from0.

1. `UsedBounds`: initial used > output.len(). This is checked before inspecting either map.
2. `GroupCount(map)`: group count >65535. Primary count is checked before spelling count.
3. `InvalidOrdinal(map,index)`: any Builtin ordinal >80. Scan all primary names, then all spelling names.
4. `EmptyValues(map,index)`: a group's value slice is empty. Scan all primary groups, then all spelling groups.
5. `DuplicateName(map,index)`: the first index whose name equals an earlier name. Check maps separately, primary first; compare earlier indices in increasing order. No custom/builtin or case normalization occurs.
6. `Representation(map)`: for each map, its row count times native row stride (primary104, spelling96), and its total extra occurrence count times extra stride (primary72, spelling64), must be representable in usize and <=isize::MAX. Extra count is the checked sum of `values.len()-1` over that map. Its accumulation and multiplication are checked. Individual valid borrowed byte slices already obey Rust's slice-size domain. This canonical unshared-extra embedding is an explicit stronger host restriction, not a native producer theorem. It does not require actual aggregate allocation or fabricate native pointers.
7. `LengthOverflow`: compute the complete required used length with checked usize additions, starting at initial used and visiting primary groups/values in their actual order. For each occurrence, add chosen name length, then3 for an empty value, or4 and the value length for a nonempty value. Reject arithmetic overflow, or a final result >isize::MAX. Capitalization does not change byte length. No capacity comparison short-circuits this full length pass.
8. `Capacity { required }`: required used length >output.len(). The required value includes the retained prefix. A valid required value exactly equal to capacity succeeds.

Every error leaves **the entire output slice** unchanged, including its prefix and unused bytes. Both maps are validated even if primary is empty, or a spelling key/value would never be consumed. Thus invalid unused spelling can be rejected where the native empty-primary path would return without reading it. All refusal variants, their precedence and atomic refusal are new host policy, not native error ABI, failure timing or rollback equivalence.

STRUCTURAL-CHAIN.md gives the separate non-circular primary/extra payload, head/tail and intermediate-next-field relation and proves exact finite iteration. The native bucket invariant remains relational and is not weakened to row-array equality: unique rows, one occupied bucket per row, exact native cached H(key), power-of-two count/mask, an empty bucket and per-resident probe inequalities imply the native lookup selects the corresponding logical group. The source independently searches actual spelling names linearly. Primary self-lookup is identity only because that invariant and unique tagged names prove it.

## Successful write

For each primary group in input order, locate its matching spelling group by real exact-key comparisons. Pair primary value occurrence j with spelling occurrence j while available. Otherwise use the primary group's canonical builtin bytes or exact custom fallback. Extra spelling occurrences are ignored. An empty spelling occurrence overrides the name with empty bytes; it does not fall back.

Supplied spelling bytes are copied verbatim regardless of capitalization. For fallback only, capitalization true changes ASCII a..z to A..Z at the first byte or immediately after an emitted hyphen. Other bytes and other positions are unchanged. This is neither lowercasing nor Unicode title casing.

Append `chosen_name + ': ' + value + CRLF` for nonempty value; append `chosen_name + ':' + CRLF` for empty value. No final blank line is added. The returned used length includes the original prefix. Output `[0..old_used)` and `[new_used..capacity)` remain byte-for-byte unchanged. Empty valid primary input returns old_used with the whole output unchanged. Map values, spelling sequences and input order remain unchanged; no cursor is exposed.

The count/representation rules are finite but not a low latency guarantee. A straightforward no-allocation implementation performs quadratic duplicate comparisons within maps plus linear spelling lookup per primary group: O(P²+S²+P*S) exact-key comparisons, with byte-comparison cost and two linear passes over the chosen output lengths/bytes. No hidden hasher or additional maximum-name policy is introduced.

## Pre-source evidence plan

MANUAL-CASES.json contains literal selected byte inputs and expected results written from the native relation/host policy, not computed by a reference implementation. Its compact buffer notation initializes a literal prefix and fills remaining capacity with0xa5; successful cases specify exact used bytes and retain the sentinel suffix. Four count-boundary cases are repeat-literal construction plans, not materialized arrays or claimed executions. OVERFLOW-OBLIGATIONS.md records impossible-to-practically-materialize size boundaries as algebra, not fictitious safe slices or test passes.

No production source, generator, behavioral model, native interpreter or test execution was authored or run in this design task. Root must review and admit the exact contract/expectations before source construction.
