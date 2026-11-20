#!/usr/bin/env python3
"""Authenticate the Node #115 GossipRpcResponse prefix-boundary packet."""
import hashlib
import json
import importlib.util
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

def fail(message):
    raise AssertionError(message)

def main():
    packet = json.loads((HERE / "records.json").read_text())
    target = ROOT / "artifacts/node/115/hl-node"
    data = target.read_bytes()
    if hashlib.sha256(data).hexdigest() != PIN or packet["target_sha256"] != PIN:
        fail("target digest")
    spec = importlib.util.spec_from_file_location(
        "elf_support", ROOT / "research/work-items/RE-001-node115-registry-row-labels/verify.py"
    )
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    image = helper.Image(data)
    start, end = int(packet["target"]["start"], 16), int(packet["target"]["end"], 16)
    body = image.get(start, end - start)
    if hashlib.sha256(body).hexdigest() != packet["target"]["sha256"]:
        fail("complete FDE body hash")
    output = subprocess.run(
        ["objdump", "-d", "-Mintel", f"--start-address={start:#x}",
         f"--stop-address={end:#x}", str(target)],
        check=True, capture_output=True, text=True,
    ).stdout
    rows = re.findall(r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+(.+?)\s*$", output, re.M)
    if not rows or int(rows[0][0], 16) != start or int(rows[-1][0], 16) >= end:
        fail("instruction partition")
    actual = {(f"0x{address}", " ".join(instruction.split("<", 1)[0].replace(",", ", ").split()))
              for address, instruction in rows if instruction.strip()}
    for address, mnemonic, operands in packet["facts"]:
        expected = " ".join((mnemonic + (" " + operands if operands else "")).replace(",", ", ").split())
        if (address, expected) not in actual:
            fail("missing fact: " + repr((address, mnemonic, operands)))
    print(json.dumps({
        "target_sha256": PIN,
        "fde": [hex(start), hex(end)],
        "body_bytes": len(body),
        "instructions": len(rows),
        "captured_target_executed": False,
        "prefix_contract": "no post-success remaining-length comparison in authenticated parent body"
    }, indent=2))

if __name__ == "__main__":
    main()
