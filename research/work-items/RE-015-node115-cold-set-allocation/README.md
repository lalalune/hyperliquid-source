# RE-015 Node #115 cold set allocation

The merge delegate packet leaves open whether the first set growth copies
the table template or starts empty. This trace follows the original cold
descriptor through the transform gate into the allocation-success branch.

The original descriptor words for bucket mask, growth remaining and item
count are zero. The table control pointer is relocated to 0x450150, whose
first 16 bytes are 0xff. The transform gate tests growth remaining at
0x474ba86 and branches to 0x474bc81 when it is zero. The branch supplies
reserve count 1 and flag 1. The slot at 0x64eaf88 resolves to 0x4743990.

The initializer adds the existing item count to the reserve count. On the
cold input, the adjusted request is 1 and the old effective capacity is
zero. The small-allocation branch selects four buckets. The layout uses
24 bytes per bucket, aligns that span to 16 bytes and adds one control
byte per bucket plus 16 more. The allocation request is therefore 116
bytes. On success, the new control pointer is 96 bytes past the allocation
start and the imported memset fills 20 bytes with 0xff.

The old item-count load at 0x4743b5e is followed by a zero branch at
0x4743b65. That branch reaches the publication block without entering the
migration loop. The descriptor stores the new control pointer, mask 3,
growth remaining 3 and item count 0. The original mask is zero, so the
old allocation free branch is skipped. There are no initial strings.
This describes the state before the caller retries and probes/inserts.

Scope: original cold descriptor, reserve count 1, allocation success.
General resizing, allocator internals, uninitialized bucket contents and
downstream transform tags are outside this evidence. The two code owners
were decoded from the pinned Node #115 capture and never executed.
