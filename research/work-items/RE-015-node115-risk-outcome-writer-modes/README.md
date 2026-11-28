# RE-015 — Node #115 risk outcome record writer modes

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [risk outcome record set packet](../risk-outcome-record-set-115/) establishes the serializer-first family. This packet follows the distinct direct record writer reached by the layout-B set caller at `0x22715fb`.

The writer at `0x28ffab0` takes its mode byte from serializer +0xb. For mode zero it hands field count 5 to the array header helper `0x25e7940`. Mode one hands the same count to the map header helper `0x25e7670` and emits keys through the string writer. Both paths check header return word 2 before field output.

The output order is outcome, settleFraction, details, nameAndDescription and sideNames. The outcome value loads input +0x90. The next two values take pointer and length from input +8/+0x10 and +0x20/+0x28. The two nested values use the layout-B helpers `0x22e6fc0` and `0x2276c90`. This recovers a mode and helper binding distinct from the prior +0x1b writer. Other mode values, nested value implementations and error ownership remain outside scope.

Run `PYTHONPATH=tools python3 research/work-items/RE-015-node115-risk-outcome-writer-modes/verify.py` for static verification.
