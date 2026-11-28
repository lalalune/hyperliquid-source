# RE-017: recover positional checkpoint tracker delay

The checkpoint export packet in #7220 identified both keyed and positional MessagePack tracker emission. The map reader in #7222 did not establish which positional elements can be omitted. This packet follows the array path through its count checks and output layout.

The outer reader calls `0x30432a0` at `0x32cfce9`. That adapter tests its remaining-element count before reading. Zero returns the absent sentinel, which lets the outer caller build a whole tracker with the known +0.0 delay constructor. On the selected successful present-element route, the adapter decrements the count and calls `0x33b2a30` to parse the tracker. An error result follows a different outer branch.

The selected inner sequence path treats an exhausted count before element 4 as invalid length at index 4. With element 4 present, it calls scalar decoder `0x46f3cb0` and accepts tag 9. The word moves through stack `+0x10` to tracker `+0x88`. When this is the final remaining element, the parser consumes it and proceeds without calling the tail decoder. With another element present, it calls the tail decoder, so an omitted sixth element is distinct from an omitted fifth one.

The outer reader stages the returned or defaulted tracker at `rsp+0xf20`. Its normal copy chain passes through `+0x6cb0` and `+0x80a0` to `+0x6390` in the assembled state at `rsp+0x4060`. That places the timer word at historical state `+0x23b8`, as for the map encoding. These are selected branches and do not validate all truncations or overlong snapshots.

Run `python3 -B research/work-items/RE-017-node115-replay-delay-positional-read/verify.py` from the root. The verifier checks FDE and relocation identity, count branches, scalar and optional tail calls, and the final stack-slot arithmetic.
