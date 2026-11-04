# Independently literal pre-reference hand cases

Forty actual-input cases, manually derived before any reference source exists. Full twenty-byte keys, physical rows, weights, head/live and every selected occurrence are stored in cases.json; inputs.tsv has only the six admitted input fields. Expected fields remain in separate parent-side files. The serialization step copies literal expectations; it performs no lookup, sum, threshold computation or instruction evaluation.

Native anchors refer to the five complete authenticated bodies and the sealed conditional proof. Bounds/Order cases are explicitly host policy. No malformed transport, native tree evaluator, dynamic native effect trace or physical memcmp load trace is claimed. H28 does not distinguish equivalent early-stop behavior.

## H01 — empty

No rows and no selected occurrences: B=S=0, and strict0<0 is false.

Expected: `H01	ok	0	0	0`. Anchors: `0x57f54eb..0x57f5582`, `0x4d3e27d..0x4d3e299`, `0x4d3e2e4..0x4d3e302`.

## H02 — empty_misses

Every actual query misses the empty map; repeated queries do not invent weight. B=S=0.

Expected: `H02	ok	0	0	0`. Anchors: `0x57f54eb..0x57f5582`, `0x4d3e27d..0x4d3e299`, `0x4d3e2e4..0x4d3e302`.

## H03 — empty_head_bounds

Empty backing requires head0; this is host Bounds, not a native failure result.

Expected: `H03	bounds`. Anchors: `HOST-CONTRACT.md Library admission1..4`.

## H04 — empty_live_bounds

live1 exceeds capacity0, so Bounds before any ordering or lookup.

Expected: `H04	bounds`. Anchors: `HOST-CONTRACT.md Library admission1..4`.

## H05 — bounds_before_order_head

head2 is outside capacity2. Physical keys are descending, but Bounds has priority over Order.

Expected: `H05	bounds`. Anchors: `HOST-CONTRACT.md Library admission1..4`.

## H06 — bounds_before_order_live

live3 exceeds capacity2; do not wrap repeatedly or return Order first.

Expected: `H06	bounds`. Anchors: `HOST-CONTRACT.md Library admission1..4`.

## H07 — order

Valid bounds, but logical keys2,1 descend. Order is a chosen host refusal.

Expected: `H07	order`. Anchors: `HOST-CONTRACT.md Library admission1..4`.

## H08 — inactive_zero_live

The nonempty backing has valid head1 but no live rows. Both MAX weights and descending inactive keys are ignored.

Expected: `H08	ok	0	0	0`. Anchors: `HOST-CONTRACT.md Library admission1..4`, `0x57f54eb..0x57f5582`, `0x4d3e27d..0x4d3e299`, `0x4d3e2e4..0x4d3e302`.

## H09 — empty_live_strict_head

The safe host requires head<capacity even when live0. Native inert-state permissiveness is not copied.

Expected: `H09	bounds`. Anchors: `HOST-CONTRACT.md Library admission1..4`.

## H10 — inactive_rows

Only physical rows1,2 are live, logical keys1,2. Found weights3+2=5; query9 misses. S=2+3=5, so10<15.

Expected: `H10	ok	5	5	1`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4d3e24c..0x4d3e299`, `0x4e40729..0x4e40759`, `0x4d3e2e4..0x4d3e302`.

## H11 — zero_weight

Two found occurrences each add0; S0. Strict equality is false.

Expected: `H11	ok	0	0	0`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4d3e2e4..0x4d3e302`.

## H12 — all_misses

Queries0 and2 are below/above sole key1. B0, S5, so10<0 is false.

Expected: `H12	ok	0	5	0`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4d3e2e4..0x4d3e302`.

## H13 — single_hit

One hit contributes5 and total is5;10<15 is true.

Expected: `H13	ok	5	5	1`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4d3e2e4..0x4d3e302`.

## H14 — selected_repeats_unsorted

Selected order2,1,2 is preserved:7+5+7=19, S12. No selected sorting/uniqueness admission;24<57.

Expected: `H14	ok	19	12	1`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4e44c65..0x4e44c77`, `0x4e40729..0x4e40738`, `0x4d3e2e4..0x4d3e302`.

## H15 — contiguous_last_equal

Contiguous key1 selects its last row weight7, not2. S2+7+11=20;40<21 is false.

Expected: `H15	ok	7	20	0`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4d3e2e4..0x4d3e302`.

## H16 — contiguous_repeated_equal

Each key1 occurrence selects weight7: B14, S20;40<42. Deduplicating selected input would change this.

Expected: `H16	ok	14	20	1`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4e44c65..0x4e44c77`, `0x4e40729..0x4e40738`, `0x4d3e2e4..0x4d3e302`.

## H17 — wrapped_seam_override

Logical rows are key1/2,key1/3,key1/11,key2/17. Query1 equals physical row0 seam, selecting3 immediately rather than11. S33;66<9 false.

Expected: `H17	ok	3	33	0`. Anchors: `0x57f5516..0x57f553a`, `0x57f5699`, `0x4d3e24c..0x4d3e299`, `0x4e40729..0x4e40759`, `0x4d3e2e4..0x4d3e302`.

## H18 — wrapped_seam_repeats

Each repeated seam key contributes3, so B9,S33,false. A global-last-equal fault contributes33 and would pass66<99.

Expected: `H18	ok	9	33	0`. Anchors: `0x57f5516..0x57f553a`, `0x57f5699`, `0x4e44c65..0x4e44c77`, `0x4e40729..0x4e40738`, `0x4d3e2e4..0x4d3e302`.

## H19 — wrapped_first_segment_last

Seam key2>query1, so search first segment physical2,3 and select last key1 weight7. S13+17+2+7=39;78<21 false.

Expected: `H19	ok	7	39	0`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4d3e24c..0x4d3e299`, `0x4e40729..0x4e40759`, `0x4d3e2e4..0x4d3e302`.

## H20 — both_segments_selected_order

Queries3,2,1 contribute17,13,7. B37,S39;78<111 true. Both spans and unsorted selected input are used.

Expected: `H20	ok	37	39	1`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x57f5516..0x57f553a`, `0x57f5699`, `0x4d3e24c..0x4d3e299`, `0x4e40729..0x4e40759`, `0x4d3e2e4..0x4d3e302`.

## H21 — wrapped_second_segment_last

Seam key2<query3; second segment has two key3 rows, so last weight11 is used. S21;42<33 false.

Expected: `H21	ok	11	21	0`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4d3e24c..0x4d3e299`, `0x4e40729..0x4e40759`, `0x4d3e2e4..0x4d3e302`.

## H22 — wrapped_hits_and_late_miss

Found weights2+3+11=16; final query9 misses without replacing the saved sum. S21;42<48 true.

Expected: `H22	ok	16	21	1`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x57f5516..0x57f553a`, `0x57f5699`, `0x4d3e24c..0x4d3e299`, `0x4e40729..0x4e40759`, `0x4d3e2e4..0x4d3e302`.

## H23 — contiguous_nonzero_head

Live span ends exactly at capacity. Inactive first-row MAX is excluded; B=S=5.

Expected: `H23	ok	5	5	1`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4d3e24c..0x4d3e299`, `0x4e40729..0x4e40759`, `0x4d3e2e4..0x4d3e302`.

## H24 — exact_end_no_wrap

head2+live2 equals capacity4, so there is no wrapped second segment. Query9 misses despite inactive physicalrow0 key9. B=S=10.

Expected: `H24	ok	10	10	1`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4d3e24c..0x4d3e299`, `0x4e40729..0x4e40759`, `0x4d3e2e4..0x4d3e302`.

## H25 — total_saturation_only

B is exactly MAX. Raw total is MAX+1, independently clamped toMAX.2MAX<3MAX.

Expected: `H25	ok	18446744073709551615	18446744073709551615	1`. Anchors: `0x4e44c65..0x4e44c77`, `0x4e40729..0x4e40738`, `0x4d3e2e4..0x4d3e302`.

## H26 — selected_saturation_only

Each hit is2^63; exact selected sum2^64 clamps toMAX while S remains2^63.2*S=2^64<3*MAX.

Expected: `H26	ok	18446744073709551615	9223372036854775808	1`. Anchors: `0x4e44c65..0x4e44c77`, `0x4e40729..0x4e40738`, `0x4d3e2e4..0x4d3e302`.

## H27 — both_saturations

Both exact sums are2*MAX and clamp independently toMAX; wide comparison is true.

Expected: `H27	ok	18446744073709551615	18446744073709551615	1`. Anchors: `0x4e44c65..0x4e44c77`, `0x4e40729..0x4e40738`, `0x4d3e2e4..0x4d3e302`.

## H28 — post_saturation_misses

First hit saturates the selected value; later misses leave it unchanged. This expected value cannot distinguish an observationally equivalent early stop.

Expected: `H28	ok	18446744073709551615	18446744073709551615	1`. Anchors: `0x57f55a0..0x57f5608`, `0x4e44dab..0x4e44ddf`, `0x4e44c65..0x4e44c77`, `0x4e40729..0x4e40738`, `0x4d3e2e4..0x4d3e302`.

## H29 — strict_equality

2*S=6 and3*B=6; strict comparison rejects equality.

Expected: `H29	ok	2	3	0`. Anchors: `0x4d3e2e4..0x4d3e302`.

## H30 — strict_above

2*S=8<9=3*B; just above the small threshold passes.

Expected: `H30	ok	3	4	1`. Anchors: `0x4d3e2e4..0x4d3e302`.

## H31 — strict_below

2*S=4 is not below3*B=3.

Expected: `H31	ok	1	2	0`. Anchors: `0x4d3e2e4..0x4d3e302`.

## H32 — near_max_equality

The weights sum exactlyMAX. B=2*MAX/3, so3B=2MAX=36893488147419103230; equality is false and requires high limbs.

Expected: `H32	ok	12297829382473034410	18446744073709551615	0`. Anchors: `0x4d3e2e4..0x4d3e302`.

## H33 — near_max_above

S remainsMAX; B is one above2MAX/3, so3B exceeds2MAX by3. True with exact wide products.

Expected: `H33	ok	12297829382473034411	18446744073709551615	1`. Anchors: `0x4d3e2e4..0x4d3e302`.

## H34 — near_max_below

S remainsMAX; B is one below2MAX/3, so3B is2MAX-3. False.

Expected: `H34	ok	12297829382473034409	18446744073709551615	0`. Anchors: `0x4d3e2e4..0x4d3e302`.

## H35 — unsigned_first_byte

Unsigned first bytes7f<80<ff are correctly ordered. Queriesff,80 contribute9+5=14;S16,32<42.

Expected: `H35	ok	14	16	1`. Anchors: `0x57f5522`, `0x57f55bf`, `0x57f55e6`, `0x57f564f`, `0x57f567a`, `import0x64dfb50 symbol12 memcmp`, `0x4d3e2e4..0x4d3e302`.

## H36 — unsigned_twentieth_byte

First19 bytes are equal; byte20 unsigned7f<80<ff determines order and hits. B14,S16,true.

Expected: `H36	ok	14	16	1`. Anchors: `0x57f5522`, `0x57f55bf`, `0x57f55e6`, `0x57f564f`, `0x57f567a`, `import0x64dfb50 symbol12 memcmp`, `0x4d3e2e4..0x4d3e302`.

## H37 — middle_byte_order

Zero key < key with byte11=1 < key with byte10=1. Queries consume the full20-byte key, B9+5=14,S16,true.

Expected: `H37	ok	14	16	1`. Anchors: `0x57f5522`, `0x57f55bf`, `0x57f55e6`, `0x57f564f`, `0x57f567a`, `import0x64dfb50 symbol12 memcmp`, `0x4d3e2e4..0x4d3e302`.

## H38 — twentieth_byte_miss

The query differs only at byte20, so it misses. Comparing only a common prefix would incorrectly add7.

Expected: `H38	ok	0	7	0`. Anchors: `0x57f5522`, `0x57f55bf`, `0x57f55e6`, `0x57f564f`, `0x57f567a`, `import0x64dfb50 symbol12 memcmp`, `0x4d3e2e4..0x4d3e302`.

## H39 — wrapped_order_failure

Logical order from head1 is key3,key1,key2; the live seam descends, so host Order.

Expected: `H39	order`. Anchors: `HOST-CONTRACT.md Library admission1..4`.

## H40 — empty_selection_nonempty_total

Empty selected sequence contributes0, but every live row is still summed to12.24<0 is false.

Expected: `H40	ok	0	12	0`. Anchors: `0x57f54eb..0x57f5582`, `0x4d3e27d..0x4d3e299`, `0x4d3e2e4..0x4d3e302`, `0x4d3e24c..0x4d3e299`, `0x4e40729..0x4e40759`, `0x4d3e2e4..0x4d3e302`.

