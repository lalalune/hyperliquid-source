#!/usr/bin/env python3
"""Whitelist, authenticate and regenerate this packet without target execution."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
packet = Path(__file__).resolve().parent
sys.path.insert(0, str(packet.parents[2] / 'tools'))
from node115_wide_byte_select import verify_packet

verify_packet(packet)
print('Packet whitelist, source hashes and authenticated regeneration OK')
