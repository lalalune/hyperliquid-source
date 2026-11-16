# Node115 owned TCP payload receive

This host-event adapter starts after a supplied complete header and reuses the
existing frame-plan length gate and 4,000,000-byte chunk intervals. It owns a
zero-initialized buffer, retains partially filled chunks across Pending, and
advances outer progress only when the current chunk completes. A nonempty
request receiving zero bytes returns EOF and discards the buffer; supplied
errors and a timeout supplied after Pending likewise terminate without returning partial payload.
Complete payload ownership and the flag-one transform decision are returned
to the caller; decompression remains a separate operation.

`Pending`, `Timeout` and error events are host inputs, not recovered native raw
tags or timer policy. This source models no socket, scheduler, allocator
failure equivalence, native future ABI, cancellation or end-to-end connection
lifecycle. Host events must correspond to the selected native read boundary;
invalid overlong input is rejected as adapter misuse.
