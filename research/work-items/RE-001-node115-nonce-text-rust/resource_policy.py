#!/usr/bin/env python3
"""Pure arithmetic of the chosen host policy, not an allocation oracle."""

NATIVE_NORMAL_MAX = 1 << 59


def classify_required_length(required: int, pointer_bits: int) -> dict:
    if type(required) is not int or required < 0:
        raise ValueError("required length must be a mathematical natural number")
    if pointer_bits not in (16, 32, 64):
        raise ValueError("this policy table selects 16/32/64-bit host arithmetic")
    isize_max = (1 << (pointer_bits - 1)) - 1
    within_native_count = required <= NATIVE_NORMAL_MAX
    within_host_bytes = 8 * required <= isize_max
    # Native normal growth is supplied only as proof context. The independent
    # source Vec need not choose this spare capacity or these allocation calls.
    native_capacity = 0 if required == 0 else max(4, 1 << (required - 1).bit_length())
    return {
        "required_initialized_words": str(required),
        "host_pointer_bits": pointer_bits,
        "isize_max": str(isize_max),
        "required_bytes": str(required * 8),
        "within_native_normal_count": within_native_count,
        "within_host_representable_bytes": within_host_bytes,
        "chosen_capacity_admission": "admit" if within_native_count and within_host_bytes else "host-capacity",
        "native_normal_capacity_context": str(native_capacity),
        "native_capacity_within_proved_domain": native_capacity <= NATIVE_NORMAL_MAX,
    }
