# Manual expectation notes

The42 small cases were written literally from the reviewed name-selection/append relation and chosen error passes. They are not outputs of reconstructed source, a Python serializer, a target interpreter, or a reference parser. The subsequent metadata-only check parsed JSON, checked unique case IDs and compared the byte length of each already written expected string/hex literal with its already written used_result; it did not compute any output from inputs. No behavioral qualification is claimed.

A01..A09 separate zero-capacity/empty-map success, prefix/suffix preservation, empty values, actual group order and repeated occurrence processing. N01/N02 use raw table boundary entries0=`accept`,80=`x-xss-protection`; N03 uses1=`accept-charset`. N04 keeps builtin0 distinct from custom`accept`, so only the latter receives CUSTOM. N05 keeps case-distinct keys.

S01's literal count is1 retained prefix +13 bytes for`x-CuStOm: a`CRLF +9 bytes for`X-Test:`CRLF +11 bytes for`X-Test: b`CRLF =34. This discriminates per-occurrence exhaustion from a whole-group override. S02 has3 six-byte lines; S03 emits only one; S04 first emits5 bytes for the empty supplied name, then6 for Y, so11. S07 uses the secondary map in the opposite order from the primary groups and therefore requires real name lookup.

T01 preserves all hyphens and uppercases only x/y. T02's internal EsT remains as supplied; only x and the t after the hyphen change, giving X-TEsT. T03 begins0xe9, then a, hyphen,b: only b changes, giving e9 61 2d 42 before punctuation. T04 leaves supplied spelling x-cUsToM unchanged. V01 preserves embedded0/CR/LF/ff in a raw value; it is explicitly not HTTP grammar validation.

B01/B02 differ by one output byte and establish exact-fit versus whole-buffer-unchanged refusal. B03's used3 exceeds its actual2-byte buffer and must win even over the invalid ordinal. R07/R08/R10 deliberately mix invalidities across maps/indices to enforce global pass order. R09 makes capacity insufficient too, but duplicate refusal wins. Each error case requires the entire original buffer unchanged, not just its prefix.

The4 count plans are deliberately compact repeated-literal input descriptions, not pre-generated65535/65536-element files. C02 reaches a duplicate at second index after a permitted65535 count, avoiding a valid-max-size quadratic stress. C01/C03/C04 fail count immediately. They are realizable future host test constructions; none has been instantiated or run here. Oversized arithmetic/storage cases remain algebraic obligations in OVERFLOW-OBLIGATIONS.md instead of fabricated safe slices.

Structural-chain and bucket proofs are independent of these finite examples. The structural list relation names actual primary/extra fields and proves traversal; it does not use the literal outputs as premises. All raw-body and helper limitations remain those of the sealed native evidence.

Prior credit also includes the later baseline raw-export preservation correction e6409d494f294fff9659b80e70debbe9d3810814 after initial header packet3a46c477333f0f797216d6ca11016bc87e10d979, as established by the independent node_scout review. Both original native scout files remain unchanged. PR2943's byte-identical feed remains context only; no source implementation is proposed for it.

## EXPAND

- Root review of exact host refusal passes, structural chain relation and literal cases precedes production authoring.
- Future source review must prove identical first/second-pass selection, checked widths and no post-write failure; finite examples cannot replace that proof.
- No additional hasher, bucket constructor, transport grammar, allocator model or native error emulation is needed or authorized by this design.
