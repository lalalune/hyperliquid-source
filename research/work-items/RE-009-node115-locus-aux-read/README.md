# RE-009 node #115 routes named checkpoint Locus aux through a skip

Node #115's named checkpoint writer emits a 17th Locus field, `aux: []`, while the Locus restore reader has 16 materialized keys. The ordinary reader treats `aux` as an unknown key. It consumes the empty-array marker and resumes the map with no `aux` state value. A fixture for this named reader can model `aux` as a serialization detail separate from the 16 restored values.

Target is Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source baseline is `2da45cb0a761cff6b478e40421699857d87a94df`. All addresses are ELF virtual addresses.

[Earlier Locus work](../RE-008-locus-msgpack-fields-115/README.md) mapped the 16 restore fields and the generic skip arm. This packet follows the literal `aux` input through the short-string classifier and the canonical empty-array branch. The [binary context witness](../RE-009-abci-binary-context-115/README.md) supplies the surrounding checkpoint reader.

| Step | Selected instruction path |
| --- | --- |
| Key | The enclosing Exchange reader calls `0x332c430`. A freshly fetched fixstr marker `a3` masks to length 3 and reaches `0x332d56a`. After the successful UTF-8 branch, it passes the key bytes and length to `0x2fbbd20`. |
| Unknown dispatch | The matcher handles three-byte keys with an unsigned first-byte index `first - 'b'` and admits indices 0 through 20 to its lookup table. The first byte of `aux` lies outside that range, so `0x2fbbe76` returns success tag 9 with field index 16. The parent's table `0x73da1c` sends index 16 to the skip arm `0x332ca10`. |
| Empty array | The skip arm calls `0x31d5e50` to consume one value. In the freshly fetched marker branch, it advances the input cursor by one byte, classifies `90` as a fixed array, and takes the zero-count branch. On an ordinary depth budget this restores the depth word and returns success tag 9 without a child-value read. |
| Resume | The parent branches straight to `0x332c717` on tag 9. That instruction decrements the remaining map-pair count and either continues with the next key or reaches map completion. |

Run from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-locus-aux-read/verify.py
```

The [offline run](offline-log.txt) checks the pinned ELF and the synthetic bytes of one canonical `aux` pair followed by another field marker. The next marker serves as cursor evidence and its payload is outside the test. The controls distinguish a known-key first-byte class, an array marker with one child and an incorrect skip argument. For manual inspection, use LLVM objdump 23.1.4 with `-d --x86-asm-syntax=intel --start-address=START --stop-address=END artifacts/node/115/hl-node` and the addresses in `windows.txt`.

The scope is the selected named form under ordinary parser returns and available depth. Other skip forms, malformed input, positional checkpoints, live replay and root equality remain outside the result. No captured code was executed.
