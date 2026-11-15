# Node #115: owner offsets feeding selected digest-producer gates

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This maps the selected `0x54cae80` call's arguments through `0x5afa3b0` to the `0x5373e40` producer, extending the selector mapping in open #6048 and the producer gate findings in #6746 and #6747.

At selector entry, `rbp` retains the input owner pointer. `0x54caea4..0x54caeab` puts `owner+0xdb8` into a stack word. In the selected call at `0x54cb062..0x54cb078`, the arguments are `owner+0x3e50`, the owner itself, `owner+0x3f08`, and a pointer to that stack word. `0x5afa3b0` passes the first argument on as the producer's `rsi` while preserving the third and fourth arguments; the producer preserves the third pointer and reads the fourth argument's pointed-to word.

Consequently, in this selected same-owner path, the producer's gate inputs are: comparison owner `owner+0x3f08`, comparison lookup word at `owner+0x3f60` (the comparison owner's `+0x58`), binary64 factor at `owner+0x3e88` (the selected store's `+0x38`), and membership-search object `owner+0xdb8` with its comparison qword at `owner+0xdc8`. These are address and data-flow relationships, not claims about field names, pointer validity or authority. The claim assumes the owner and call remain unchanged over these instructions and normal returns; it does not resolve population of those fields.

The referenced open packets describe conditional selected branches rather than accepted global policy. This join does not prove authenticated votes, a canonical root, successful checkpoint replay, or full node equivalence. No progress gate changes.

Run `python3 research/work-items/RE-017-node115-digest-producer-owner-gates/verify.py` to check target digest, instruction anchors, direct-call targets and mutation controls without target execution. `windows.txt` records disassembly.
