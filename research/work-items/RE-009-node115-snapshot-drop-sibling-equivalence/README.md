# RE-009: compare snapshot value and ring cleanup bodies

The inline tree value cleanup target at 0x2428930 and the nested ring cleanup target at 0x24aa210 have equal 952-byte FDE spans. The comparison decodes 26 displacement pairs. All other 848 bytes in each span match. The only differing destinations are three calls from 0x2428930 to 0x242a760 whose peers call 0x24ab350. This connects the previously separate cleanup paths and leaves the two helpers outside the equivalence claim.

The verifier checks the pinned ELF digest, all unmasked bytes, each declared displacement target and corruption controls. The FDE lines and disassembly are included. No target instructions execute.
