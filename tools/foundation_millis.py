"""Shared ELF/instruction helpers retained for the node #115 validators.

Extracted from the historical research module; no retired-target entry point.
"""
import argparse


import calendar


import datetime


import hashlib


import json


from pathlib import Path


import re


import struct


import subprocess


import sys


from elf_index import sections


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode_export(output, start, end, body):
    rows = []
    for line in output.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)(.*)$', line)
        if match:
            address, raw = int(match[1],16), bytes.fromhex(match[2])
            # GNU objdump wraps instructions longer than 7 bytes: the bytes
            # past the seventh continue on an addressed row whose mnemonic
            # field is empty. Merge such a row into the previous instruction
            # instead of counting it as a separate instruction.
            if rows and not match[3].strip() and address == rows[-1][0]+len(rows[-1][1]):
                rows[-1] = (rows[-1][0], rows[-1][1]+raw)
            else:
                rows.append((address, raw))
    cursor = start
    for address, raw in rows:
        require(address == cursor, 'Noncontiguous disassembly or off-by-one address')
        cursor += len(raw)
    require(cursor == end and b''.join(raw for _,raw in rows) == body, 'Disassembly bytes/extent changed')
    return dict(rows)


