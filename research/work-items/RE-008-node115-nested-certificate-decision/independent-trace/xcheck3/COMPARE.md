# Comparison of the second reader's answer with the packet (round 4)

Done by the author after receiving `ANSWER.md`, against the frozen corpora (`ORACLE_FROZEN.txt` FREEZE 4) and
`relations-digest.tsv`. The reader saw neither.

## Q1: the five preimages

The reader's hex strings for F1..F5 were searched, as whole strings, in the `preimage` column of
`cases-digest.tsv`: each occurs exactly once, in the row the frame was taken from.

| Frame | Row | Equal |
| --- | --- | --- |
| F1 | `d0013` (word 0 = 0x100000001 = 2^32 + 1, the 8-byte payload class: marker `fd`; earlier text of this file said 4-byte, which was wrong, the preimage in both files has `fd0100000001000000`) | yes |
| F2 | `d0014` (word 0 = 0x8000000000000000, the 8-byte class) | yes |
| F3 | `d0199` (random: 1-, 4- and 8-byte classes) | yes |
| F4 | `d0200` (random: 1-, 2- and 4-byte classes) | yes |
| F5 | `d0201` (random: 1-, 2- and 4-byte classes) | yes |

The reader's rules (prefix, tag byte, field order, the three thresholds and markers, raw 20 and 32 byte arrays,
no lengths) are DB1, DB5, MS2, VS1, PV1..PV4, PA1, PA2 of `relations-digest.tsv`. Its hash parameters (rate 136,
delimiter 0x01, output 32, offsets of the state fields) are DB6, KU1, KF1. It did not check the round constants
of the permutation (it recognised the structure); that is covered by the RE-009 packet and by
`tests/digest.rs`.

## Q2: the recovery wrapper

| Point | Reader | Packet row | Equal |
| --- | --- | --- | --- |
| each 32-byte half passed byte reversed | yes (0x1536ad1..0x1536b29) | RC1 | yes |
| recovery id for v in {0,1,2,26,27,28,29,34,35,36,37,254,255} | 0,1,err6,err6,0,1,err6,err6,0,1,0,1,0 | RC2..RC5, `cases-recover.tsv` group `v-sweep` | yes (the corpus gives the same for all 256 values) |
| digest passed unchanged | yes | RC1 | yes |
| three callees named from their checks | parse_compact, recover, pubkey_serialize of libsecp256k1 | SP1, SR1, RC8 | yes (the same three names; the packet says "named from", not "proved") |
| serialize: length 0x41, flags 2 (uncompressed) | yes | RC8 | yes |
| address | bytes 12..32 of Keccak-256 of the 64 bytes after the format byte, tag 0 | RC9 | yes |
| failures | error 6 for bad v, error 3 for parse or recover failure, serialize result ignored | RC4, RC6, RC7, RC8 | yes |

The points of the reader's list "Not verified" (the error enum behind `0x14cca30`, the permutation constants,
library internals beyond the entry bodies, the lazy context, the undefined `rcx` of the size pass, the clock
reads) are also not claimed by the packet, except the clock reads (DB2, argued from the stack use).

## What this does and does not show

Two readings of the same disassembly agree on the preimage of five frames and on the wrapper's behaviour. The
reader was given the frame layout and the addresses of the callees from the author's reading, so it was not asked
to find the structure; it is from the same model family as the author; it chose nothing (the frames were mine);
it did not run anything. It is a second reading, not a native differential run. Its agreement does not make the
packet's reading of the other message variants, the curve library or the callers of the decision any firmer.
