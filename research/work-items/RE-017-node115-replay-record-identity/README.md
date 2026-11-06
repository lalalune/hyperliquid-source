# RE-017 · Replay record identity and successor

Target Linux x86-64 Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The [expanded result packet](../RE-017-abci-expanded-result-115/README.md) establishes the selected replay worker and its rejection boundary. This packet traces the record fields and local expected word before block processing.

The worker seeds its expected word at stack +0x168 from its fifth argument. A next-record result tag other than 1 takes the prior exit. For tag 1 and a non-null first payload pointer, let M be 0x8000000000000001. If record +0x28 equals M, the worker compares record +0x60 with the expected word. If only record +0xb8 equals M, it compares +0x58. Otherwise it compares +0xe8. A mismatch reaches the existing diagnostic before the two selected reference increments.

After a match, the selected normal path calls the existing callback helper with selector zero and then one. It reloads the marker at record +0x28. This later test selects record +0x60 if that word equals M, or record +0xb0 otherwise. The worker increments the selected word and substitutes all ones on wrap, then stages it at stack +0x168. The later marker load is distinct from the earlier selection, and intervening helpers can affect aliased data. The claim identifies both local projections without assigning source-level names to the record fields.

For tag 1 with a null first payload pointer, the selected arm calls the same callback helper with selector one and an argument pair whose first word is zero. It atomically decrements the second payload pointer's leading word and calls the release slot only when that decrement yields zero. Both continuations return to next-record retrieval with no explicit expected-word store on this arm. These observations assume valid result and reference-count pointers and normal helper returns.

Replay with `python3 research/work-items/RE-017-node115-replay-record-identity/verify.py` from the repository root. It checks selected byte windows and transfers and exercises the marker and successor cases in a synthetic model.
