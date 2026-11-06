# RE-017 · Wide queue segment append

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Both the 88-byte record writer at 0x581a2d0 and the terminal writer at 0x581be00 have a cross-segment path that requests 0xb20 bytes. Their initialization clears the three words at +0xb08, +0xb10 and +0xb18 before linking the new segment.

In the record writer the selected first attempt writes the old segment base plus 32 to the candidate's +0xb00, then attempts to replace a null +0xb08 link. On failure the returned pointer supplies the predecessor for another attempt and the candidate's base is recomputed from that predecessor. The later retry loop repeats that calculation and compare-exchange. The terminal writer has three analogous link sites using +0xb08. These selected paths use the same segment layout for allocation even though their final payload and flag writes differ. Full concurrent ownership and wrap behavior remain open.

Run `python3 research/work-items/RE-017-node115-wide-queue-segment-append/verify.py` from the repository root to verify the authenticated byte windows.

Both writers also test the old segment's low readiness dword for all ones and require the local advancement flag before attempting to replace the producer descriptor's segment pointer. The successful path stores the current reservation word to old segment +0xb18 before setting bit 32 at +0xb10 with a locked OR. This publication is separate from the link attempt and applies to the old segment.

The corresponding reader checks bit 32 and compares the old segment's +0xb18 watermark against its reader index before recycling a segment distinct from the currently selected one. It advances the older pointer, clears the old base, link and readiness words and attempts to attach the recycled segment. Three compare-exchange sites use +0xb08, and the selected final failure passes 0xb20 as the release size. These windows connect the writer's published watermark to the reader's eligibility checks.
