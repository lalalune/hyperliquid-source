#!/usr/bin/env python3
"""Input transport admission only; no expected values or target instruction use."""
import re
import struct


def require(ok,message):
    if not ok:raise ValueError(message)


class Reader:
    def __init__(self,data):
        require(len(data)<=1<<20,"frame limit");self.data=data;self.pos=0

    def take(self,n):
        require(0<=n<=len(self.data)-self.pos,"truncated frame")
        v=self.data[self.pos:self.pos+n];self.pos+=n;return v

    def scalar(self,fmt):
        return struct.unpack("<"+fmt,self.take(struct.calcsize("<"+fmt)))[0]

    def option(self):
        v=self.scalar("B");require(v in (0,1),"option domain");return v

    def count(self,maximum):
        n=self.scalar("I");require(n<=maximum,"count limit");return n

    def bytes(self):
        return self.take(self.count(65536))


def decode(raw):
    r=Reader(raw);require(r.take(4)==b"VR01","magic")
    owned=r.option()
    request=dict(tag=r.scalar("Q"),bytes=r.bytes().hex());terminal=r.scalar("Q")
    description="shell::wait_retry";delays=None;cleanup=None;cleanup_error=None
    if not owned:
        try:description=r.bytes().decode("utf-8",errors="strict")
        except UnicodeDecodeError as e:raise ValueError("description UTF-8") from e
        if r.option():delays=[r.scalar("Q") for _ in range(r.count(256))]
    else:
        if r.option():cleanup=dict(tag=r.scalar("Q"),bytes=r.bytes().hex())
        if r.option():cleanup_error=r.scalar("Q")
    attempts=[r.scalar("Q") if r.option() else None for _ in range(r.count(256))]
    sleeps=[[r.scalar("i"),r.scalar("q"),r.scalar("q")] for _ in range(r.count(1024))]
    require(r.pos==len(raw),"trailing frame")
    return dict(mode="owned" if owned else "retry",request=request,terminal=terminal,
                description=description,delays=delays,cleanup=cleanup,
                cleanup_error=cleanup_error,attempts=attempts,sleeps=sleeps)


def lines(data):
    require(bool(data) and data.endswith(b"\n"),"complete nonempty batch")
    result=[];ids=set()
    for line in data.splitlines(keepends=True):
        require(line.endswith(b"\n") and b"\r" not in line,"canonical LF")
        fields=line[:-1].split(b"\t");require(len(fields)==2,"two fields")
        identity,payload=fields
        require(re.fullmatch(rb"C[0-9]{6}",identity) is not None,"opaque ID")
        require(identity not in ids,"duplicate ID");ids.add(identity)
        require(len(payload)%2==0 and re.fullmatch(rb"[0-9a-f]+",payload) is not None,"lowercase hex")
        require(len(payload)<=2<<20,"encoded frame limit")
        result.append((identity.decode("ascii"),decode(bytes.fromhex(payload.decode("ascii")))))
    return result
