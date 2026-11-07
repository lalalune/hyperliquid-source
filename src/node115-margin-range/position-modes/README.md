# Node115 position modes

Independent `no_std` projection of the selected position mode dispatch and
direct arithmetic at node115 `0x448b800..0x448b967`.

The API maps raw modes 0–4 to no division, exact division, two opaque margin
table variants, or capped division; computes signed magnitudes and floor
quotients; and saturates the active offset with a positive-part projection.
Original units, risk names, table internals, ABI and panic behavior remain out
of scope.
