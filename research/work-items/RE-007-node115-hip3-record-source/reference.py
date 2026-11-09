#!/usr/bin/env python3
"""Independent object-to-MessagePack reference; no captured target execution."""
import datetime
import hashlib
import json
import struct
import sys
from pathlib import Path


def pack(value):
    if isinstance(value, bool):
        return bytes([0xc3 if value else 0xc2])
    if isinstance(value, int):
        if value < 128:
            return bytes([value])
        for limit, marker, fmt in ((256, 0xcc, '>B'), (65536, 0xcd, '>H'),
                                   (1 << 32, 0xce, '>I'), (1 << 64, 0xcf, '>Q')):
            if value < limit:
                return bytes([marker]) + struct.pack(fmt, value)
        raise ValueError('outside unsigned64 domain')
    if isinstance(value, str):
        data = value.encode('ascii')
        prefix = bytes([0xa0 + len(data)]) if len(data) < 32 else bytes([0xd9, len(data)])
        return prefix + data
    if isinstance(value, list):
        return bytes([0x90 + len(value)]) + b''.join(map(pack, value))
    if isinstance(value, dict):
        return bytes([0x80 + len(value)]) + b''.join(pack(k) + pack(v) for k, v in value.items())
    raise TypeError(type(value))


def timestamp(year, ordinal, seconds, nanos):
    # A year differing by 400 has the same Gregorian month/day sequence.
    proxy_year = 2000 + year % 400
    day = datetime.date(proxy_year, 1, 1) + datetime.timedelta(days=ordinal - 1)
    y = f'{year:04}' if 0 <= year < 10000 else f'{year:+05}'
    hour, tail = divmod(seconds, 3600)
    minute, second = divmod(tail, 60)
    leap, fraction = divmod(nanos, 1_000_000_000)
    result = f'{y}-{day.month:02}-{day.day:02}T{hour:02}:{minute:02}:{second + leap:02}'
    if fraction:
        precision = 3 if fraction % 1_000_000 == 0 else 6 if fraction % 1000 == 0 else 9
        result += '.' + f'{fraction:09}'[:precision]
    return result


DATES = [
    (0, 1, 0, 0), (1, 365, 86399, 0), (1900, 60, 3723, 1),
    (2000, 60, 45296, 999), (2024, 366, 86399, 1000),
    (9999, 365, 59, 999999), (10000, 1, 3600, 1000000),
    (-1, 1, 0, 999999999), (-10000, 60, 86399, 999000000),
    (-262143, 365, 86399, 1), (262142, 365, 86399, 999999999),
    (2000, 60, 59, 1000000000), (2000, 60, 59, 1000000001),
    (2024, 60, 86399, 1999999999), (2023, 60, 3661, 1000001),
    (2024, 1, 59, 1001000000), (2024, 1, 59, 1000001000),
    (100000, 366, 86399, 999999999), (-100000, 366, 86399, 999999999),
    (2001, 32, 7200, 123456000),
]
COUNTS = [0, 1, 127, 128, 255, 256, 65535, 65536, (1 << 32)-1, 1 << 32, (1 << 64)-1]
LABELS = ['Na', 'UserDisabled', 'ValidatorDisabled', 'm']
KEYS = ['last_settlement_time', 'deploy_time', 'n_reserve_deployments_used', 'disabled_state', 'm']


def main():
    rows = ['# mode tag m count year1 ordinal1 seconds1 nanos1 year2 ordinal2 seconds2 nanos2 wire_hex']
    maximum = 0
    for mode in range(2):
        for tag in range(4):
            for m in range(2):
                for count in COUNTS:
                    for index, first in enumerate(DATES):
                        second = DATES[(index * 7 + 3) % len(DATES)]
                        values = [timestamp(*first), timestamp(*second), count, LABELS[tag], bool(m)]
                        wire = pack(dict(zip(KEYS, values)) if mode else values)
                        maximum = max(maximum, len(wire))
                        fields = [mode, tag, m, count, *first, *second]
                        rows.append(' '.join(map(str, fields)) + ' ' + wire.hex())
    text = '\n'.join(rows) + '\n'
    root = Path(__file__).resolve().parents[3]
    fixture = root / 'src/node115-hip3-disabled-record/tests/reference-vectors.txt'
    if '--write' in sys.argv:
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(text)
    else:
        assert fixture.read_text() == text
    print(json.dumps({'cases': len(rows)-1, 'maximum_fixture_bytes': maximum,
                      'sha256': hashlib.sha256(text.encode()).hexdigest(),
                      'method': 'Independent Python datetime and recursive object packer, not native execution'}, indent=2))


if __name__ == '__main__':
    main()
