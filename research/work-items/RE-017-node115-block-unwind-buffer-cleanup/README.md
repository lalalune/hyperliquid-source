# RE-017 · Block caller unwind buffer cleanup

The block caller at `0x4fcb590` supplies its stack cell at +0x128 to `0x4f35280` on the selected cleanup path. The continuation separately calls `0x4f2fd70` for stack +0x20 and then enters an atomic update before unwind resumption. The +0x128 helper has an early-exit tag at the first word, `0x8000000000000000`, that skips both buffer calls. Zero skips the first call only. Ordinary nonzero passes +8 and +0, and then reaches the same secondary guard as zero. That guard tests +0x18 and when nonzero tail-calls the same indirect slot with +0x20 and +0x18. In both cases the third argument is zero.

This records the selected block unwind ABI and the different effects of the sentinel and empty buffer. It leaves the buffer contents and type, actual callback effects and other unwind paths open.

Run `python3 research/work-items/RE-017-node115-block-unwind-buffer-cleanup/verify.py` from the root to check the pinned capture, full extent, direct edge with corruption control and continuation bytes.
