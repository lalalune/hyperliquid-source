# Node115 book-ring append

Independent `no_std` projection of the nonfull ring-slot calculation in the
selected node115 book insert append arm.

`append_slot` validates capacity/head/length and returns `(head+length)%capacity`
plus the next length. A full ring returns `MustGrow`; `append_after_grow` applies
the same calculation to a caller-supplied post-grow capacity. Payload
construction, grow/allocation, registration and key derivation remain outside
scope.
