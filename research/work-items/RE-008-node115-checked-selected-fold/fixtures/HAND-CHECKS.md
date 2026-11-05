# Hand checks independent of future implementation

These checks were written by the fixture author from the retained complete
native exports and the accepted conditional proof, before any new Rust source
or reference evaluator. They are not an independent second reviewer's verdict,
an executed model or a passed test. Root and the native peer can independently
review the exact literals. The credited design-v1 is preserved unchanged under
inputs/design-v1; the following three cases are additive amendments.

F07 has capacity3, head2,count2: active physical indexes are2 then0, keys1 and3
with weights2 and3. Physical-zero second span has length1. Query1 takes the
tail and finds2; query2 takes the tail and misses; query3 takes the seam
equality shortcut and finds3; query4 reaches the one-row second span and misses.
Thus sum5, consumed4, remaining0, last key-tree(node0,index3).

T04's map root0 has occupancy0 and height1. Its all-keys-exhausted path at
0x43517e0 chooses child0 after decrementing height. Child1 has key1:9 and
height0, so query1 selects9. The key cursor yields its sole key at(node0,0).
This is an admitted conditional topology, not evidence of a native producer.

T05's map leaf0 contains keys1..11 with matching weights1..11. Query0 misses
before the first key;1,6,11 find weights1,6,11;12 scans all11 and misses.
The sum is18; five selected occurrences are consumed, last=(node0,index4).

## Original cases, checked against literal data

| Cases | Manual selection/arithmetic and cursor check |
| --- | --- |
| A01 | No nodes or occurrences; status1,sum0,consumed0,remaining0,last=None. |
| A02 | Two leaf occurrences, empty map misses twice;sum0,last(0,1). |
| A03 | One matching zero-weight row;sum0,last(0,0). |
| A04 | M+0=M without carry; two occurrences consumed, complete. |
| A05 | Key node order is(node1,0)=1, (node0,0)=2, (node2,0)=3. M+1=2^64, so status0,sum0 after two and remaining1; last is root(0,0). Internal yield already prepares right subtree. Second call starts sum0, selects7 at(2,0), completes remaining0. Third call starts with remaining0 and returns status1,sum0,consumed0 while preserving last(2,0). |
| A06 | (M-1)+3=2^64+1; status0,sum1, last(0,1), one occurrence remains. |
| A07 | Key1 misses,2 adds M,3 misses,4 adds1 with carry; status0,sum0,consumed4,remaining0,last(0,3). |
| A08 | Structural keys3,1,3 select7,5,7;sum19,last(0,2). No sorting or deduplication. |
| A09 | M+M=2^65-2, low64=M-1; status0 after second occurrence, remaining1,last(0,1). |
| F01 | Nonwrapped duplicate keys3 select the last row, weight31. |
| F02 | Active logical order is1:10,3:300,3:30,3:31,5:50. Seam key3 at physical0 selects30 immediately, rather than300 or31. |
| F03 | Same physical map; selected1:10,4:miss,5:50 gives60 and consumes3. |
| F04 | Active indexes4,5,6,0,1,2. Keys1,2,4,6 select10,21,40,61;sum132. Inactive physical3 with all-FF key is ignored. |
| F05 | Active indexes1,2 only: keys2:20 and4:40. Queries1,3,5 miss;sum60,consumed5. Both inactive slots remain irrelevant. |
| F06 | Query8 finds80,7/9 miss;sum80,consumed3. |
| T01 | Root first3 has30 and shadows root second3:31 and all descendant3 weights. Queries1,3,4,5 give10+30+0+50=90. |
| T02 | Query3 passes root2, reaches right leaf and chooses its first3:300, not301. |
| T03 | Queries0..6 find1:10,2:20,3:30,4:40,5:50;0/6 miss. Sum150. |
| K01 | Actual node sequence is(3,0),(1,0),(4,0),(0,0),(5,0),(2,0),(6,0), keys1..7. All weights1;sum7,last(6,0). |
| K02 | Same node order: M then0 then1 overflows at(4,0), leaving four. Continuation climbs two ancestor levels to root(0,0), then visits(5,0),(2,0),(6,0), each weight1; second result4. No injected frontier is used. |
| K03 | Fresh left descent reaches empty node1, climbs to root key2, and prepares right node2. Yields2:20 then3:30;sum50,last(2,0). |
| K04 depth8 | Literal nodes0..8 have eight child0 edges; only node8 holds key1. Native descent's quotient path reads eight child links;sum9,consumed1,last(8,0). |
| K04 depth9 | Literal nodes0..9 have nine child0 edges; only node9 holds key1. The initial remainder step plus eight-edge group reaches node9;sum9,consumed1,last(9,0). |
| K05 | Eleven distinct key occurrences in one node all equal1, each finds weight1;sum11,last(0,10). |
| U01 | Literal A begins00 then nineteenFF bytes;B begins01 then nineteen00 bytes. Unsigned lexicographic A<B. Actual key order B,A yields3+2=5,last(0,1). |
| U02 | All first19 bytes are zero; last bytes are7f/80/ff. Actual key order ff,80,7f yields4+2+1=7,last(0,2). |

For every complete one-call fixture, consumed equals the literal key count;
remaining0 and last is the final actual structural occurrence. The only
incomplete first calls are A05,A06,A09,K02; A07 is overflow with remaining0.
Only A05/K02 continue; A05's additional third call qualifies the chosen
persistent-last observation when no further key is yielded. Expected sums are literal decimal strings, never
calculated by a fixture generator. No public next/peek field was added.

## Refusal checks and limits

The twelve literal REFUSALS entries exercise Bounds, Shape, Links, Topology,
Height and MapOrder. R01 and R05 explicitly distinguish category precedence;
R09 is a locally reciprocal cycle disconnected from an otherwise valid root,
so Links does not hide the Topology branch. R10 has valid reciprocal edges
but unequal leaf depths. R11 has equal depths and valid links but wrong map
order. R12 has a nonempty arena with root=None. These are safe host refusals,
not outcomes from native malformed state.

Representation overflow is specified but not fabricated as an enormous
allocated fixture. Shape bounds already imply each finite native node's
payload offsets fit its leaf/internal extent. Actual native base-address
nonwrap/disjointness remains a relation premise, not a source constructor
ability to inspect unknown native addresses.

## EXPAND

Review all literal identities, values and host error precedence independently;
then freeze these unchanged files before source. Future test results must be
reported separately, including any real mistake or post-freeze amendment.
