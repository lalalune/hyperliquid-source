# Node115 compact five-byte projection

Independent `no_std` implementation of the recovered 80-byte-row projection:
copy exactly source offsets `0x45..0x4a` into five-byte output rows, preserving
source order.

The original allocation, dangling-empty representation, result producer,
downstream observer and 176-byte full-result copy remain out of scope.
