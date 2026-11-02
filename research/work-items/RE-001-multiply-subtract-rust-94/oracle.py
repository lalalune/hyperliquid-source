#!/usr/bin/env python3
"""Unbounded-integer oracle for the statically derived scalar-subtract leaves.

No registers, flags, decoded instructions, reference implementation or Rust
source are read. This computes whole integers rather than a limb algorithm.
"""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
R = 2**64


def result(kind, args):
    a, b, c, x, y, scalar = args
    if kind == "w":
        before = a + R * b + R**2 * c
        operand = x + R * y
        product = scalar * operand
        borrow = int(before < product)
        low = (before - product + borrow * operand) % R**2
        adjusted = (scalar - borrow) % R
        return (low % R, low // R, adjusted), adjusted
    if kind == "n":
        return ((a - scalar * x) % R, scalar), scalar
    raise ValueError("unknown operation")


def words(value, count):
    return tuple(value // R**j % R for j in range(count))


def entropy(label, count):
    raw = b"".join(hashlib.sha256(f"subtract-v1:{label}:{i}".encode()).digest()
                   for i in range((count + 3) // 4))
    return tuple(int.from_bytes(raw[8*j:8*j+8], "little") for j in range(count))


def fixtures():
    hand = [
        ("w-hand-no-borrow", (100,200,300,3,0,7), (79,200,7), 7),
        ("w-hand-borrow-one", (3,4,0,5,9,1), (3,4,0), 0),
        ("w-hand-borrow-two", (3,4,0,5,9,2), (R-2,R-6,1), 1),
        ("w-hand-zero", (11,22,33,7,8,0), (11,22,0), 0),
        ("n-hand-plain", (100,999,999,3,999,7), (79,7), 7),
        ("n-hand-wrap", (5,999,999,3,999,7), (R-16,7), 7),
        ("n-hand-high-discard", (0,999,999,2,999,R-1), (2,R-1), R-1),
    ]
    for label, args, out, ret in hand:
        if result(label[0], args) != (out, ret):
            raise ValueError(f"hand calculation: {label}")
        yield label[0], label, args
    edges = (0,1,2,2**32-1,2**32,2**63,R-1)
    for i, scalar in enumerate(edges):
        for j, x in enumerate(edges):
            for k, y in enumerate(edges):
                product = scalar * (x + R*y)
                low, top = product % R**2, product // R**2
                before = (0, (product-1) % R**3, product, product+1,
                          R**3-1, low + min(R-1,top+1)*R**2,
                          low + max(0,top-1)*R**2)
                for index, n in enumerate(before):
                    yield "w", f"w-boundary-{i}-{j}-{k}-{index}", (*words(n,3),x,y,scalar)
                yield "n", f"n-boundary-{i}-{j}-{k}", (y,0,R-1,x,R-1,scalar)
    for i in range(512):
        args = entropy(f"random-{i}",6)
        for kind in ("w","n"):
            yield kind, f"{kind}-varied-{i}", args
    for pattern in range(3):
        raw = b"".join(x.to_bytes(8,"little") for x in entropy(f"alias-{pattern}",10))
        out = tuple(int.from_bytes(raw[32+8*j:40+8*j],"little") for j in range(3))
        for offset in range(16,57):
            operand = tuple(int.from_bytes(raw[offset+8*j:offset+8*j+8],"little") for j in range(2))
            for kind in ("w","n"):
                yield kind, f"{kind}-overlap-snapshot-{pattern}-{offset}", (*out,*operand,(0,1,R-1)[pattern])


def generate():
    inputs, outputs, counts = [], [], {"w":0,"n":0}
    for kind, label, args in fixtures():
        counts[kind] += 1
        inputs.append("\t".join((kind,label,*(f"{x:016x}" for x in args)))+"\n")
        out, ret = result(kind,args)
        outputs.append(f"{label}\t{','.join(f'{x:016x}' for x in out)}\t{ret:016x}\n")
    files = {"inputs.tsv":"".join(inputs).encode(),"expected.tsv":"".join(outputs).encode()}
    freeze = {"target_sha256":SHA,"windows":[["0x565ee40","0x565ee9b"],["0x565eea0","0x565eeba"]],
              "method":"static whole-integer model; no captured execution or instruction evaluation",
              "counts":counts,"cases":sum(counts.values()),
              "oracle_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "sha256":{k:hashlib.sha256(v).hexdigest() for k,v in files.items()}}
    files["freeze.json"]=(json.dumps(freeze,indent=2,sort_keys=True)+"\n").encode()
    return files


def check():
    files=generate()
    for name, raw in files.items():
        if (HERE/"fixtures"/name).read_bytes()!=raw:
            raise ValueError(f"frozen fixture drift: {name}")
    return json.loads(files["freeze.json"])


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=Path)
    args=parser.parse_args()
    if args.out:
        args.out.mkdir(parents=True,exist_ok=False)
        for name, raw in generate().items(): (args.out/name).write_bytes(raw)
    else:
        print(json.dumps(check(),indent=2,sort_keys=True))
