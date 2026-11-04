# RE-001: node115 outbound consensus age, retry and connection-fence gates

Component: consensus. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The outbound worker at `0x5a7f6f0` has separate receive, connect and send continuations. This packet addresses its admission gates after a queued item is obtained. Receive/TLS/waker machinery is retained as context and is not a new synchronization claim.

The first converted age is dropped when it is ordered, differs from positive infinity, and exceeds **5.0**. Equality5.0 passes. Positive infinity and unordered comparisons take the bypass edge. A dropped item increments the local counter at +0x160 with unsigned saturation and releases the item before repolling.

A connection attempt requires raw connection state2. When a failure timestamp exists, the converted elapsed value blocks an attempt if it is below **2.0**, positive infinity or unordered. Exactly2.0 admits an attempt. The connect continuation is built with binary64 **2.0** as its timeout input. Pending retains outer state4. A completed error records a new failure timestamp and calls through the error carrier. A completed success sets the success flag, clears the failure timestamp marker and resets the drop counter; it updates the connection-time fence on a reconnect or after an earlier success.

Before sending, age is sampled again. Positive infinity or unordered comparison is substituted with0.0 at this boundary. An available connection and age <=5.0 are required. If a saved connection timestamp is present, an item strictly older than it is rejected: seconds compare signed and the fractional DWORD compares unsigned, with equality accepted. The send continuation receives binary64 **20.0**, distinct from the connect input. Pending stores outer state5. A send error records the failure timestamp and reaches the saturating drop-counter increment. Successful send releases the item and repolls without that increment.

The code proves numeric inputs and branch policy. Clock-difference helper semantics and actual units, TCP connect/send implementations, error reporting, runtime scheduling and network delivery remain unresolved. Relations use supplied converted ages and connection state at each boundary, including special floating-point values; they do not pretend to execute the opaque connect between those boundaries.

Prior source-location inventories and #211's gossip RPC timeout study concern different boundaries. #2566 addresses local-versus-remote routing, and #2580 addresses external-transaction forwarding order. Neither recovers this worker's age/backoff/fence conjunction. The full native export and selected literal bindings preserve the context for review.

Prior #1778 studies lower TCP frame deadlines, a different boundary from the queued-item age and reconnect fence here.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| worker | `0x5a7f6f0..0x5a8024b` | 2907 | 596 |

The denominator is 1 complete FDEs, **2907 bytes /596 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **36 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-consensus-outbound-age-gates/export_disassembly.py
python3 research/work-items/RE-001-node115-consensus-outbound-age-gates/verify.py --controls
python3 research/work-items/RE-001-node115-consensus-outbound-age-gates/relations.py
python3 -m unittest discover -s tests -p test_node115_consensus_outbound_age_gates.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
