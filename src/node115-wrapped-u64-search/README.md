# Node115 u64-key wrapped-search family

Independent MIT safe no_std source for complete leaves2ee0640 and4551810,
with actual32/56-byte original layouts measured together in one packet.
The own API accepts logical sorted keys plus capacity/rawhead and returns raw
status/index coordinates. It does not recover the original descriptor API/ABI.

`probe` preserves ordinary last-equal/insertion behavior and the wrapped
pivot-equality shortcut. A uniform last-equal search changes duplicate results
at the physical seam. `None` refuses inputs outside the finite measured geometry
(capacity<=32), not a native malformed-input error claim.

See [contract/evidence](../../research/work-items/RE-001-wrapped-u64-search-115/README.md).
No allocation/dependencies/Cargo graph, original compiler recipe, Linux build,
signature/authentication policy, target-byte equivalence or whole-component gate.
