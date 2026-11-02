#!/usr/bin/env python3
"""Static arithmetic identities, not instruction/target execution or callback tests."""
import hashlib
import json
from pathlib import Path
import verify


def four_digits(value):
    hundreds = (((value >> 2) * 0x147b) & 0xffffffff) >> 17
    thousands = ((hundreds * 0xcd) & 0xffff) >> 11
    remainder = (value - 100 * hundreds) & 0xffffffff
    tens = ((remainder * 0xcd) & 0xffff) >> 11
    return bytes((0x30 | thousands,
                  0x30 | ((hundreds - 10 * thousands) & 0xff),
                  0x30 | tens,
                  0x30 | ((remainder - 10 * tens) & 0xff)))


def suffix(index, correction):
    combined = (index + correction) & 0xffffffff
    high_group = combined >> 6
    first = 0x30 + (combined >= 0x280)
    second = ((high_group if combined < 0x280 else high_group + 0xf6) | 0x30) & 0xff
    low_group = ((combined & 0xff) >> 1) & 0x1f
    tens = (low_group * 26) >> 8
    third = 0x30 | tens
    fourth = 0x30 | ((low_group - 10 * tens) & 0xff)
    return combined, high_group, low_group, bytes((first,second,0x2d,third,fourth))


def main():
    data = (verify.ROOT/'artifacts/node/94/hl-node').read_bytes()
    verify.require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == verify.SHA, 'node94 identity')
    elf = verify.Elf(data)
    table = elf.read(0x250675,733)
    derived, expected = [], []
    for value in range(10000):
        actual = four_digits(value)
        want = f'{value:04d}'.encode('ascii')
        verify.require(actual == want, 'four-digit identity')
        derived.append(actual)
        expected.append(want)
    rows = []
    for index, correction in enumerate(table):
        combined, high, low, actual = suffix(index,correction)
        verify.require(0 <= high <= 12 and 0 <= low <= 31, 'observed table-derived numeric groups')
        expected_suffix = f'{high:02d}-{low:02d}'.encode('ascii')
        verify.require(actual == expected_suffix, 'table-dependent suffix arithmetic')
        rows.append(dict(index=index,table_byte=correction,combined=combined,
                         group_high=high,group_low=low,callback_arguments_hex=actual.hex()))
    for low in range(32):
        verify.require((26 * low) >> 8 == low // 10, 'low-group quotient identity')
    print(json.dumps(dict(target_sha256=verify.SHA,small_unsigned_domain=[0,9999],
                         decimal_cases=len(derived),decimal_result_sha256=hashlib.sha256(b'\n'.join(derived)+b'\n').hexdigest(),
                         independent_decimal_sha256=hashlib.sha256(b'\n'.join(expected)+b'\n').hexdigest(),
                         suffix_rows=rows,table_sha256=hashlib.sha256(table).hexdigest(),
                         suffix_domain='only all 733 guarded raw indexes; no source-level validity or calendar claim',
                         captured_binary_executed=False,callbacks_executed=False,
                         limits='Mathematical identities from authenticated operand facts; not a target interpreter or runtime behavior comparison'),indent=2))


if __name__ == '__main__':
    main()
