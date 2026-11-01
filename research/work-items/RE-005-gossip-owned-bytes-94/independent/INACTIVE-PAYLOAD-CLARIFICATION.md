# Post-seal clarification of excluded inactive Option payload

This note clarifies illustrative raw-byte wording in UTF8-PROOF.md and
WIRE-PROOF.md, preserved unchanged under pre-source seal
59d2455ee7fbbe5aa47bfa77103a07409c74daa9f0c7b6c99125b4ab51f76963.
It changes no logical expectation, domain, protocol or source behavior.

The native validator writes the Option presence byte at result+16 and BL at
result+17. On None the latter byte is inactive and is excluded from the frozen
logical projection, regardless of its concrete value. Its value is not always
the transformed lead byte:

- If the required second byte is missing, no later lead transformation has
  happened, so BL can retain the original lead byte.
- For the width3 EF path after an admitted second byte, AND BL,FE at0x157a36e
  leaves EE; a missing third byte can therefore write inactive EE.
- For width4 after an admitted second byte, LEA RBX,[RCX+2] at0x157a3a0
  overwrites the entire register before checking for the third byte. Missing
  third or fourth bytes therefore write `(valid_up_to+2) mod256` as inactive
  payload. Earlier F1..F3 transformations to0..2 do not generally survive that
  instruction. For example F1 80 at index0 writes inactive2, not transformed0.

The validator also leaves six following metadata padding bytes unwritten. The
primary may copy them, but neither they nor the inactive None payload are part
of the semantic corpus. Frozen records retain only None or Some1/2/3 and the
first failing scalar's starting byte offset. The original seals remain exact;
this is a separate chronological clarification, not a regenerated authority.
