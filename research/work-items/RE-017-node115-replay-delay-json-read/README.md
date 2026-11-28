# RE-017: trace checkpoint delay through the JSON reader

The MessagePack restore path in #7222 mapped the checkpoint's `advt.adu` word to historical state `+0x23b8`. The JSON path has separate field selectors and a numeric parser. This packet traces its selected object path and checks whether it emits the same layout.

The JSON Exchange caller at `0x40909db` calls body `0x3efb050`. Its table entry 57 selects a branch with the `advt` diagnostic literal and a normal call to nested body `0x4000c30`. That body's table entry 4 selects the branch associated with the literal `adu`. After the JSON field separator, it calls scalar parser `0x3fbc520` and stages the low eight bytes of the successful scalar payload in `rsp+0x3a8`. The successful object assembly places the word at `rsp+0x2a8`, offset `+0x88` from its tracker base `rsp+0x220`. The nested child's output copies preserve that offset.

The parent moves the nested value through `rsp+0x2978`. Its absent whole-tracker path calls the same zero-initializing constructor observed in the MessagePack reader. Either normal path stages the 0xb8-byte tracker at `rsp+0x608` and copies it to historical output `+0x2330`. The explicit JSON field therefore reaches historical `+0x23b8`. An omitted `adu` inside a present object uses its own missing-field diagnostic instead of the parent constructor.

Run `python3 -B research/work-items/RE-017-node115-replay-delay-json-read/verify.py` from the root. The verifier reads the pinned ELF and checks the selected FDEs, table entries, scalar field and return slots, copy widths, and parent constructor slot. The finite numeric conversion internals and full checkpoint replay remain outside the packet. No captured code is executed.
