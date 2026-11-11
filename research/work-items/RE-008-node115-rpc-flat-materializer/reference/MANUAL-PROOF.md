# Independent manual RPC handcases

This is a provisional mathematical fixture set for root's
`ROOT-RPC-CONTRACT.v3.md`, not a native execution or a completed source gate.
The selected target is node #115, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The proposed new semantic scopes are flat search
`0x57f5ee0..0x57f60cc` and materializer `0x50f95f0..0x50f9720`.
This author read the whole v3 contract and manually derived these expectations
without reading or running a reference implementation, corpus generator,
captured instruction evaluator, or library implementation. These fixtures are
one independent mathematical derivation within the same project and captured
target lineage, not an independent organization or second native oracle.

## Representation and mathematical rule

`handcases.json` defines all 18 complete 32-byte key strings. A physical row
contains a catalogue key ID and an explicit nonzero decimal u64 value. This is
a complete input representation: substitute the named catalogue string exactly;
there is no implicit key prefix, padding, missing physical row, or generated
expected field. Every case lists all physical rows, including inactive ones.
The `K00` through `K09` strings differ only in their last byte. Other key names
have no semantic meaning beyond their explicitly supplied bytes.

The manual method is order statistics, with the contract's explicit seam rule:

1. Write the live logical row order by starting at physical `head`, taking
   `live_len` rows, and wrapping once if necessary.
2. If there is a wrapped second segment, its first logical index is
   `a = capacity - head`. An equal query to that segment's first key selects
   exactly index `a`, including when other equal keys lie on either side.
3. Otherwise list the indices of all equal live keys and select their final
   index. On absence count live keys strictly below the query. This count is
   the insertion index, not a physical position.
4. A hit's physical position is the row's actual slot in step 1. Read only
   that row's supplied value.
5. For materialization, take query results in query order. Stop on the first
   miss. Any miss makes the final value `None`; otherwise it is the complete
   sequence, with repeats preserved. Zero queries produce `Some([])`.

No binary-search loop, midpoint update, register machine, or target instruction
is reproduced here. The proof below explains every complete case separately.

## Case-by-case derivation

In the table, a logical sequence lists catalogue key IDs in live order. Physical
indices and supplied values are stated in the frozen JSON. `M(k)` means absent
with insertion index `k`; `H(i)` means hit at logical index `i`. The table is a
manual explanation of the JSON, not an executable comparator.

| Case | Logical live order and reason | Standalone query results | Materializer |
| --- | --- | --- | --- |
| H01 | Empty, no physical allocation and no query. | No lookups. | `Some([])`; no query reached. |
| H02 | Empty; no key can equal K01 and zero keys are below it. | `M(0)`. | `None`, first query. |
| H03 | Empty despite four allocated physical rows; head does not make inactive rows live. | `M(0), M(0)`. | `None`, first query; neither allocated matching key is admissible. |
| H04 | `[K04]`. K03 is below, K04 equal, K05 above the only key. | `M(0), H(0), M(1)`. | `None`, first query; the later standalone hit is not reached by this materialization. |
| H05 | `[K04]` at physical 3. Head plus length equals capacity, leaving no second segment. | Three `H(0)` results, all physical 3/value 401. | `Some([401,401,401])`; three reached acquisitions require three normal-return premises. |
| H06 | `[K01,K03,K05,K07]`, contiguous. For absent K00/K02/K06/K08 the numbers of smaller live keys are 0/1/3/4. | `M(0), H(0), M(1), H(1), M(3), H(3), M(4)`. | `None`, first query. |
| H07 | `[K01,K02,K02,K02,K04]`, contiguous. Equal indices are 1,2,3, so choose 3. | `H(3)` at physical 3/value 22. | `Some([22])`. |
| H08 | `[K01,K02,K02,K04]` at physical 1,2,3,4. There is no wrap; final K02 is logical 2. | `H(2), H(0), H(3)` at physical 3,1,4. | `Some([21,10,40])`. |
| H09 | Four K02 rows in physical order 3,0,1,2; `a=1`. Seam equality overrides choosing logical 3. | Both `H(1)` at physical 0/value 20. | `Some([20,20])`. |
| H10 | The same allocated rows as H09, now logical physical order 0,1,2,3, with no wrap. | `H(3)` at physical 3/value 23. | `Some([23])`; changing head is observably significant for duplicate values. |
| H11 | `[K01,K02,K02,K02,K04]` at physical 4,5,0,1,2; `a=2`. Equal indices 1,2,3 straddle and continue after the seam. | `H(2)` at physical 0/value 20, not last equal index 3/value 21. | `Some([20])`. |
| H12 | `[K01,K02,K02,K04,K06]` at physical 3,4,5,0,1; `a=3`, seam K04. K02 is strictly below the seam and final equal index is 2. | `H(2), H(0), H(3)` at physical 5,3,0. | `Some([25,13,40])`. |
| H13 | `[K01,K02,K04,K05,K05]` at physical 4,5,0,1,2; `a=2`, seam K04. K05 is above seam and final equal index is 4. | `H(4), H(1), H(2)` at physical 2,5,0. | `Some([52,25,40])`. |
| H14 | `[K01,K02,K04,K06,K08]` at physical 4,5,0,1,2. Smaller-key counts for K03/K05/K09/K00 are 2/3/5/0. Inactive physical 3 containing K09 is ignored. | `M(2), M(3), M(5), M(0)`. | `None`, first query. |
| H15 | `[K02,K05]` at physical 4,0; `a=1`. K05 equals seam; K02 is the sole row before it. | `H(1), H(0)` at physical 0,4. | `Some([50,24])`. |
| H16 | `[K01,K02,K04]` at physical 2,3,4. `head + live_len = capacity`; physical 0 is inactive, not a seam. | `H(1), H(2)` at physical 3,4, not inactive values 999/888. | `Some([23,44])`. |
| H17 | `[K01,K03,K05,K07,K09]` at physical 1,2,3,4,0; `a=4`. The final logical row is the seam. | `H(0), H(4), H(3)` at physical 1,0,4. | `Some([11,90,74])`. |
| H18 | `[K01,K03,K05]`. K02 is missing with one smaller key. | `M(1), H(0), H(2)`. | `None`, reached count 1, empty temporary prefix. |
| H19 | Same live rows; one success precedes missing K02. | `H(0), M(1), H(2)`. | `None`, reached count 2, temporary prefix `[11]` is not returned as success. |
| H20 | Same live rows; K06 exceeds all three keys. | `H(0), H(2), M(3)`. | `None`, reached count 3, temporary prefix `[11,55]` is not returned as success. |
| H21 | Same live rows; all five queries match, including repeated K05/K01. | `H(2), H(0), H(2), H(1), H(0)`. | `Some([55,11,55,33,11])`; neither sorting nor deduplicating results is justified. |
| H22 | `[K01,E01,E10,U7f,U80,Uff]`. K01 has byte 1 equal to 0 whereas E01 has byte 1 equal to 1. E01 begins 00 and E10 begins 01. First bytes 01 < 7f < 80 < ff are unsigned. | `H(4), H(2), H(1), H(5)`. | `Some([5,3,2,6])`. Treating E01/E10 as little-endian integers reverses their order; signed-byte order also reverses relevant high-bit positions. |
| H23 | `[P7f,P80,P80,Pff]`. All keys share their first 31 bytes; byte 31 decides 7f < 80 < ff. P80 equal indices are 1 and 2, regardless of their supplied payloads. | `H(2), H(0)`, values `2^63` and `2^64-1`. | `Some([9223372036854775808,18446744073709551615])`; these are opaque value words, not native addresses or signed reference counts. |
| H24 | `[K02,K04,K06]` at physical 5,6,0, with `a=2`. Inactive K04/K06 copies at physical 1/4 do not participate. K03 has exactly one smaller live key. | `H(1), H(2), M(1)`. | `None`, reached count 3, temporary prefix `[46,60]`. |

## Premises and exact limits

The handcases concern a conditional supplied-value relation. Native
correspondence still requires the complete v3 proof, valid stable native
allocations and keys, nonoverflowing native spans, sorted live keys, exact
32-byte ordinary `memcmp` behavior, calling convention and helper frame
preservation, disjoint outputs, no concurrent mutation, and normal returns
from reached growth, tracing, locking, cleanup and diagnostic operations.

Nonzero handle words do not establish any reference-count condition. In
particular, H05/H09/H21 require normal native acquisition on EACH repeated
lookup if instantiated against native objects. The per-acquisition condition
cannot be inferred from an initially live object. H23 deliberately supplies
large opaque u64 words to the mathematical/host value projection; it does not
assert that those literal bit patterns are valid dereferenceable x86-64 object
addresses or that they are reference counts. This is a source-value boundary
case, not a concrete native address/lifetime experiment.

The prefix annotations establish lookup ordering only. They claim neither
successful native destruction nor exact ownership, allocation, ABI or unwind
effects. Failure output words other than the observed marker are not modeled
as zero or as a complete cleared vector. No allocator failure is synthesized.
All host result expectations assume any required host allocation succeeds.

`host-invalid-cases.json` separately names seven invalid supplied inputs.
They illustrate possible explicit host refusals; there is no claimed native
error tag, result, termination, side effect or OOM behavior for them.
Malformed transport encodings and a future library's exact error variants
remain outside this fixture set.

All 24 cases are small, manually justified discriminators. They are not an
all-input proof, complete boundary census, random test, target runtime result,
library execution, or proof that a particular unbuilt mutation is detected.
Independent mathematical reasoning is not an additional captured provenance.

## EXPAND

After root seals the native contract, compare these immutable expectations
with a separately reviewed high-level reference and actual authored source.
Useful semantic controls include selecting the final equal at every wrapped
seam, selecting the first contiguous equal, ignoring head or live length,
comparing only 31 key bytes, comparing payload bytes, signed-byte or
little-endian ordering, returning a successful prefix after a miss, and
deduplicating/reordering queries. Those are proposed controls, not executed
results. This set neither opens a new operation nor claims live ownership.
