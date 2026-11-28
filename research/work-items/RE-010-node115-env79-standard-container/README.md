# RE-010 — Standard MessagePack paths into the node #115 ENV79 wrappers

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet connects the enclosing wrapper at `0x149ec40` to the ENV79 result wrappers established in #7428.

The entry uses a saved marker at state +0x20 and an inline count byte at +0x21, or reads the next marker from the input cursor. For a one-entry fixmap the effective marker is `0x80` and the inline count is 1. Map16 and map32 obtain their count in big-endian order from the two or four bytes following their marker. A decoded unit count converges at `0x149ed0c`. That site sets state byte +0x20 to 1 and calls `0x14be630`, the wrapper that additionally examines the entry's value.

A standard string identifier follows the other wrapper call at `0x149ed6d`, targeting `0x14be160`. The containing helper passes its own output pointer to either wrapper. This establishes the map-vs-string boundary and where the second wrapper's extra value check fits. The enclosing configuration field name and the wrappers' callers above this helper remain open.

Run `PYTHONPATH=tools python3 research/work-items/RE-010-node115-env79-standard-container/verify.py` from the repository root. The verifier reads the pinned ELF to check instruction bytes and caller edges.
