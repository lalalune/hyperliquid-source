# RE-012 — Node #115 diagnostic time-record ordering

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet follows the time pointer at the critical-message handoff identified in #7477.

The handoff calls slot `0x64e0af8 -> 0x1507f10`. The helper copies the three consecutive dwords from the time pointer in RDX. Its outer records have stride 40. The reference time words sit at record offsets +0x18, +0x1c and +0x20.

The comparison is lexicographic. The first word uses a signed less-than test, the second uses unsigned below, and the third uses unsigned below after equal first and second words. The selected strictly-earlier case continues with a nested range of 24-byte records whose pointer and count are at outer record +8 and +0x10. Equal times take the same next-record edge as later times.

This packet covers only the time comparison and nested range handoff. The nested record interpretation and terminal diagnostic output remain outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-012-node115-diagnostic-time-order/verify.py` from the repository root for static and synthetic ordering checks.
