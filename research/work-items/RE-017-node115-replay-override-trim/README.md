# RE-017 · Replay override ring trimming

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The callback calls 0x57e6750 at 0x5a6383f. This packet covers its selected normal trimming loop after the tag-one helper result and its intervening guards.

The loop compares count at object +24 against limit at +64 as unsigned words. When count exceeds the limit, it advances the head at +16 by one, wrapping at capacity, and decrements count before passing the old head's 32-byte record to 0x4ddd0b0. It reloads count and compares it to the limit again after each call. For valid ring metadata and a helper preserving those fields, the loop consumes the excess prefix in order and stops at the limit. Other result arms and helper side effects remain open.

Run `python3 research/work-items/RE-017-node115-replay-override-trim/verify.py` from the repository root for the static edge and operand checks and synthetic ring cases.

The per-row helper also selects a storage conversion on its sentinel arm. It calls 0x51d5bb0 with descriptor +8, then rereads the head and count. The selected conversion requires the head to remain 0x8000000000000000 and the count to be below 32. It clears the old root pointer and count, collects via 0x5b8fc50, and runs the selected cursor loop until its returned head is zero. It then publishes the collected capacity, pointer and count with head index zero. The adjacent helper at 0x4ddd300 has the same sentinel and count gate after a different operation. The collector's internals and unwind effects remain separate questions.

The collector at 0x5b8fc50 sizes its initial request from the iterator count times 32. For each non-null cursor result it copies exactly the two 16-byte lanes at node plus 32 times the returned slot, then advances the destination by 32. It returns the number of rows written separately from the allocation fields. This pins the representation used here, including the absence of a separately prefixed key in this projection.
