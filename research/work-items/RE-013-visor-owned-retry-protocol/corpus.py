#!/usr/bin/env python3
"""Independent finite callback-value histories, not target execution/evaluation.

Expected sleeps use one unbounded integer total, not native registers or
production-source pair/chunk code. Inputs contain only supplied values.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct
from arithmetic import BILLION, CHUNK_MAX, DEFAULT_BITS, FIXED_BITS, duration_total, pair, valid_remainder

HERE=Path(__file__).resolve().parent


def require(ok,message):
    if not ok:
        raise ValueError(message)


def compact(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def expected(case):
    trace=[]
    command=case["request"]
    owned=case["mode"]=="owned"
    description="shell::wait_retry" if owned else case["description"]
    selected=list(FIXED_BITS) if owned else (list(DEFAULT_BITS) if case["delays"] is None else case["delays"])
    attempt_index=0
    error_serial=0
    sleep_index=0
    current=None

    def attempt(previous):
        nonlocal attempt_index,error_serial
        trace.append(["attempt",command["tag"],command["bytes"],True,None if previous is None else True])
        response=case["attempts"][attempt_index] if attempt_index<len(case["attempts"]) else None
        attempt_index+=1
        if response is None:
            trace.append(["attempt_success"])
            return None
        item=(error_serial,response)
        error_serial+=1
        trace.append(["create_error",*item])
        return item

    def drop(item):
        trace.append(["drop_error",*item])

    def refuse(kind,code=None):
        drop(current)
        if owned:
            trace.append(["drop_command",command["tag"],command["bytes"]])
            if case["cleanup"] is not None:
                v=case["cleanup"];trace.append(["drop_cleanup",v["tag"],v["bytes"]])
        return dict(code=code,outcome=kind,terminal=None,terminal_identity=None,trace=trace)

    current=attempt(None)
    outcome="succeeded"
    terminal=None
    if current is not None:
        for bits in selected:
            # Structurally distinct oracle: exact rational converter projection
            # followed by an unbounded total-nanosecond recurrence.
            remaining=duration_total(bits)
            while remaining:
                whole,nanos=pair(remaining)
                q=min(whole,CHUNK_MAX)
                request_total=q*BILLION+nanos
                trace.append(["sleep",q,nanos,1,0])
                reply=case["sleeps"][sleep_index] if sleep_index<len(case["sleeps"]) else [0,0,0]
                sleep_index+=1
                code,r,rn=reply
                trace.append(["sleep_result",code,r,rn])
                if code==0:
                    remaining-=request_total
                elif code==4:
                    if not valid_remainder(q,nanos,r,rn):
                        return refuse("invalid_remainder")
                    remaining=remaining-request_total+r*BILLION+rn
                else:
                    return refuse("unexpected_sleep_code",code)
            new=attempt(current)
            drop(current)
            current=new
            if current is None:
                break
        if current is not None:
            trace.append(["terminal",description.encode().hex(),[f"{b:016x}" for b in selected],*current,True])
            terminal=case["terminal"]
            trace.append(["create_terminal",terminal])
            drop(current)
            current=None
            outcome="exhausted"
    if owned:
        trace.append(["drop_command",command["tag"],command["bytes"]])
        cleanup=case["cleanup"]
        if cleanup is not None:
            trace.append(["cleanup",cleanup["tag"],cleanup["bytes"],True,None if terminal is None else True])
            if case["cleanup_error"] is not None:
                trace.append(["create_cleanup_error",case["cleanup_error"]])
                trace.append(["drop_cleanup_error",case["cleanup_error"]])
            trace.append(["drop_cleanup",cleanup["tag"],cleanup["bytes"]])
    return dict(code=None,outcome=outcome,terminal=terminal,
                terminal_identity=None if terminal is None else True,trace=trace)


def bytes_field(hex_string):
    value=bytes.fromhex(hex_string)
    return struct.pack("<I",len(value))+value


def frame(case):
    b=bytearray(b"VR01")
    owned=case["mode"]=="owned"
    b+=bytes([int(owned)])
    b+=struct.pack("<Q",case["request"]["tag"])
    b+=bytes_field(case["request"]["bytes"])
    b+=struct.pack("<Q",case["terminal"])
    if not owned:
        b+=bytes_field(case["description"].encode().hex())
        if case["delays"] is None:
            b+=b"\x00"
        else:
            b+=b"\x01"+struct.pack("<I",len(case["delays"]))
            for word in case["delays"]:b+=struct.pack("<Q",word)
    else:
        c=case["cleanup"]
        b+=bytes([int(c is not None)])
        if c is not None:b+=struct.pack("<Q",c["tag"])+bytes_field(c["bytes"])
        e=case["cleanup_error"]
        b+=bytes([int(e is not None)])
        if e is not None:b+=struct.pack("<Q",e)
    b+=struct.pack("<I",len(case["attempts"]))
    for a in case["attempts"]:
        b+=bytes([int(a is not None)])
        if a is not None:b+=struct.pack("<Q",a)
    b+=struct.pack("<I",len(case["sleeps"]))
    for code,seconds,nanos in case["sleeps"]:
        b+=struct.pack("<iqq",code,seconds,nanos)
    return bytes(b)


def generate_cases():
    cases=[]
    def add(name,mode="retry",description="retry",delays=None,attempts=(),sleeps=(),
            cleanup=None,cleanup_error=None,request_bytes=b"command",request_tag=7,terminal=19,policy=False):
        c=dict(id=f"C{len(cases):06d}",name=name,mode=mode,description=description,
               delays=None if delays is None else list(delays),attempts=list(attempts),
               sleeps=[list(x) for x in sleeps],
               cleanup=cleanup,cleanup_error=cleanup_error,
               request=dict(tag=request_tag,bytes=request_bytes.hex()),terminal=terminal,
               domain="new_safe_refusal" if policy else "native_conditional_protocol")
        result=expected(c)
        require((result["outcome"] in ("invalid_remainder","unexpected_sleep_code"))==policy,
                "case domain "+name)
        cases.append(c)

    # Both actual specializations and optional/default/empty schedules.
    for mode in ("retry","owned"):
        for cleanup in (None,dict(tag=0,bytes=""),dict(tag=(1<<64)-1,bytes="2f746d702f78")):
            for error in (None,0,(1<<64)-1):
                add("initial-success-unused-sleep-"+mode,mode=mode,attempts=(None,23),
                    sleeps=((4,-1,-1),(99,0,0)),cleanup=cleanup,cleanup_error=error,
                    request_bytes=b"",request_tag=0,terminal=(1<<64)-1)
    for n in range(7):
        for failures in range(n+2):
            add("explicit-failure-count",delays=[0x3ff0000000000000]*n,
                attempts=list(range(100,100+failures))+[None])
    for failures in range(5):
        add("default-failure-count",attempts=[55]*failures+[None],description="default\u0000\u03bb")
        for cleanup in (None,dict(tag=4,bytes="")):
            add("owned-failure-count",mode="owned",attempts=[55]*failures+[None],
                cleanup=cleanup,cleanup_error=18,request_bytes="\u03bb\u0000command".encode())
    add("empty-exhaustion-unused-invalid-sleep",delays=[],attempts=(1,),sleeps=((4,-1,0),))
    add("early-success-unused-invalid-suffix",delays=[0x3ff0000000000000]*3,attempts=(1,None,8),
        sleeps=((0,-1,-1),(4,-1,-1)))

    # Exact bit classes and both sides of consequential conversion boundaries.
    words={0,1,(1<<52)-1,0x0010000000000000,0x3e112e0be826d695,
           0x3f50000000000000,0x3f68000000000000,0x43dfffffffffffff,
           0x43e0000000000000,0x43e0000000000001,0x43efffffffffffff,
           0x43f0000000000000,0x43f0000000000001,
           0x7eb0c6f7a0b5ed8c,0x7eb0c6f7a0b5ed8d,0x7eb0c6f7a0b5ed8e,
           0x7ff0000000000000,0x7ff0000000000001,0x7ff8000000000000,
           0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff}
    for exponent in (0,1,991,992,1000,1013,1022,1023,1074,1075,1086,1087,2010,2027,2046,2047):
        for fraction in (0,1,(1<<51)-1,1<<51,(1<<52)-1):
            for sign in (0,1):
                words.add((sign<<63)|(exponent<<52)|fraction)
    for bits in sorted(words):
        add("raw-duration-reached",delays=[bits],attempts=(0,None))
        add("raw-duration-exhausted",delays=[bits],attempts=(0,(1<<64)-1),
            description="raw\u0000\u03bb")
    require(pair(duration_total(0x3e112e0be826d695))==(0,1),"one-nanosecond witness")
    for bits in (0x3e112e0be826d695,0x3f50000000000000,0x3ff0000000000000,
                 0x43e0000000000000,0x43efffffffffffff,0x43f0000000000000):
        seconds,nanos=pair(duration_total(bits));q=min(seconds,CHUNK_MAX)
        remainders={(0,0),(q,nanos)}
        if q:remainders.add((q-1,BILLION-1))
        if nanos:remainders.add((q,nanos-1))
        for r,rn in sorted(remainders):
            add("canonical-interruption",delays=[bits],attempts=(8,None),
                sleeps=((4,r,rn),(0,-1,-1)))
            add("equal-interruption-twice",delays=[bits],attempts=(8,9),
                sleeps=((4,q,nanos),(4,q,nanos),(0,0,0)))
    for reply in ((0,-1,-1),(0,-(1<<63),-(1<<63)),(0,(1<<63)-1,(1<<63)-1)):
        for mode in ("retry","owned"):
            add("code-zero-ignores-all-remainder",mode=mode,delays=[0x3ff0000000000000],
                attempts=(2,None),sleeps=(reply,),cleanup=dict(tag=5,bytes="e4b896"),cleanup_error=6)
    for reply in ((4,-1,0),(4,0,-1),(4,0,BILLION),(4,2,0),(4,1,1),
                  (1,0,0),(2,0,0),(3,0,0),(5,0,0),(-1,0,0),
                  (-(1<<31),0,0),((1<<31)-1,0,0)):
        for mode in ("retry","owned"):
            for cleanup in (None,dict(tag=6,bytes="00")):
                add("reached-new-refusal",mode=mode,delays=[0x3ff0000000000000],
                    attempts=(7,8),sleeps=(reply,),cleanup=cleanup,cleanup_error=9,policy=True)

    # Mixed schedules exercise order, duplicate error values, raw-bit retention
    # and zero-duration suppression without suppressing the following attempt.
    schedules=[
        [0,0x8000000000000000,0x7ff0000000000001,0xfff8000000000001],
        [0x3ff0000000000000,0,0x4008000000000000,0x3ff0000000000000],
        [0x43efffffffffffff,0x43f0000000000000,0x7eb0c6f7a0b5ed8d],
        list(DEFAULT_BITS),list(FIXED_BITS)]
    for schedule in schedules:
        for stop in range(len(schedule)+2):
            add("mixed-schedule-order",delays=schedule,attempts=[44]*stop+[None])
    rng=random.Random(0x42a290)
    for i in range(256):
        schedule=[rng.getrandbits(64) for _ in range(rng.randrange(1,7))]
        failures=rng.randrange(len(schedule)+2)
        add("deterministic-mixed-raw-history",delays=schedule,
            attempts=[rng.getrandbits(64) for _ in range(failures)]+[None],
            description="description-"+str(i%7),request_tag=rng.getrandbits(64),
            terminal=rng.getrandbits(64))
    return cases


def produce(out):
    require(not out.exists(),"fresh corpus output")
    cases=generate_cases()
    inp=bytearray();expect=bytearray();metadata=bytearray()
    events=0;domains={}
    for c in cases:
        value=expected(c)
        inp+=(c["id"]+"\t"+frame(c).hex()+"\n").encode()
        expect+=(c["id"]+"\t"+compact(value)+"\n").encode()
        metadata+=(compact(c)+"\n").encode()
        events+=len(value["trace"]);domains[c["domain"]]=domains.get(c["domain"],0)+1
    out.mkdir(parents=True)
    records={}
    for name,data in [("inputs.tsv",bytes(inp)),("expected.tsv",bytes(expect)),("cases.jsonl",bytes(metadata))]:
        packed=gzip.compress(data,mtime=0);(out/(name+".gz")).write_bytes(packed)
        records[name]=dict(bytes=len(data),sha256=sha(data),gzip_bytes=len(packed),gzip_sha256=sha(packed))
    report=dict(cases=len(cases),domains=domains,expected_events=events,files=records,
                scope="Independent abstract callback/ownership values, not captured traces or execution.",
                source_absence="No retry Rust/client authored at generation; final freeze verifier must independently check absence.")
    (out/"summary.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:report[k] for k in ("cases","domains","expected_events")}))


def main():
    p=argparse.ArgumentParser();p.add_argument("--out",type=Path,required=True);a=p.parse_args();produce(a.out)


if __name__=="__main__":
    main()
