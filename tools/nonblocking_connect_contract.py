#!/usr/bin/env python3
"""Node94 SocketAddr marshalling, nonblocking result and close-attempt contract.

Uses the separately authorized offline Python instruction evaluator. All libc
imports are symbol-bound synthetic callbacks; no socket or native capture runs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import decimal_scaled_u64 as cpu
import socket_calls_static as symbols
from fde_extents import eh_frame_records

ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'artifacts/node/94/hl-node'
PACKET=ROOT/'research/work-items/RE-012-nonblocking-connect-contract-94'
START,END=0x3cd6330,0x3cd6427
BODY_SHA='dcfd7a6f8f405424b220460fcb0647e460437cb0d8ce3059d9fa454ba6c9cb14'
SLOTS={'socket':0x5775210,'__errno_location':0x576e8d8,'connect':0x576f150,'close':0x576e708}
TOKENS={name:0x61000000+index*256 for index,name in enumerate(SLOTS)}
ERRNO=0x72000000


def need(condition,message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def signed32(value):
    return value-(1<<32) if value&(1<<31) else value


def observe(data):
    """Local structural checks also used below the identity gate for controls."""
    image=cpu.Image(data);binding=symbols.Image(data)
    need(image.fde_of(START)==(START,END),'connect helper FDE changed')
    offset=image.file_offset(START);body=data[offset:offset+END-START]
    need(sha(body)==BODY_SHA,'complete connect helper body changed')
    for name,slot in SLOTS.items():
        need(symbols.libc_slot(binding,name)==slot,'import symbol binding changed: '+name)
    _,frames=eh_frame_records(data)
    frame=next(f for f in frames if f['start']==START)
    instructions=cpu.sweep(image,START,END)
    calls=[]
    for insn in instructions:
        if insn.key==0xff and (data[insn.modrm]>>3)&7==2:
            raw=data[insn.off:insn.off+insn.size]
            need(raw[:2]==b'\xff\x15' and len(raw)==6,'unexpected indirect-call encoding')
            slot=insn.va+6+struct.unpack_from('<i',raw,2)[0]
            name=next((name for name,address in SLOTS.items() if address==slot),None)
            need(name is not None,'unbound import call')
            calls.append({'site':hex(insn.va),'slot':hex(slot),'symbol':name,'raw_hex':raw.hex()})
    need([c['symbol'] for c in calls]==['socket','__errno_location','connect','__errno_location','close'],
         'unexpected import-call set')
    rawframes={}
    for name in ('fde','cie'):
        va=frame[name];off=image.file_offset(va);size=4+struct.unpack_from('<I',data,off)[0]
        need(4<size<4096,'unqualified unwind record size')
        rawframes[name]={'va':hex(va),'size':size,'raw_hex':data[off:off+size].hex()}
    return image,{'target_sha256':cpu.SHA256,'start':hex(START),'end':hex(END),'bytes':len(body),
                  'body_sha256':sha(body),'body_hex':body.hex(),'instructions':len(cpu.sweep(image,START,END)),
                  'unwind_records':rawframes,'calls':calls,
                  'imports':{k:hex(v) for k,v in SLOTS.items()}}


def inspect(data):
    need(len(data)==91774280 and sha(data)==cpu.SHA256,'pinned node94 identity mismatch')
    return observe(data)


class Machine(cpu.Machine):
    """Only actual helper instructions execute; no fallback for another import."""
    def __init__(self,image,plan):
        super().__init__(image)
        self.plan=plan;self.events=[];self.current_errno=plan['errno']
        self.input_reads=set();self.output_writes=set()
        self.image.slots.update({SLOTS[name]:token for name,token in TOKENS.items()})

    def step(self):
        need(START<=self.pc<END and self.steps<=128,'helper control-flow/step bound exceeded')
        return super().step()

    def bounds(self,at,size,write=False):
        roles=[(cpu.OUT,16),(cpu.STACK-80,80),(ERRNO,4)]
        if not write:roles.append((cpu.INPUT,32))
        need(any(lo<=at and at+size<=lo+length for lo,length in roles),'synthetic memory escaped declared roles')
        if write and cpu.OUT<=at and at+size<=cpu.OUT+16:
            self.output_writes.update(range(at-cpu.OUT,at-cpu.OUT+size))
        if not write and cpu.INPUT<=at and at+size<=cpu.INPUT+32:
            self.input_reads.update(range(at-cpu.INPUT,at-cpu.INPUT+size))

    def load(self,at,size):
        self.bounds(at,size)
        return super().load(at,size)

    def store(self,at,size,value):
        self.bounds(at,size,True)
        return super().store(at,size,value)

    def spill(self,at,reg,size):
        self.bounds(at,size,True)
        return super().spill(at,reg,size)

    def reload(self,reg,at,size):
        self.bounds(at,size)
        return super().reload(reg,at,size)

    def arg(self,reg):
        value=self.get(reg,32)
        need(value is not None,'unknown imported-call integer argument')
        return signed32(value)

    def shift(self,kind,value,count,bits):
        # The reused evaluator has no ROL16. This helper uses only ROL AX,8;
        # its CF/OF are never consumed before the import call clobbers flags.
        # Keep those bits unknown so a later flag-dependent path fails closed.
        if kind==0 and bits==16:
            need(value is not None and count is not None,'unknown ROL16 operand')
            effective=(count&31)%16
            if effective==0:return value
            need(effective==8,'only observed ROL16-by8 is qualified')
            self.flags[0]=None;self.flags[3]=None
            return ((value<<8)|(value>>8))&0xffff
        return super().shift(kind,value,count,bits)

    def call(self,target,where):
        name=next((name for name,token in TOKENS.items() if token==target),None)
        need(name is not None,'unmodeled call target')
        pointer=False
        if name=='socket':
            self.events.append(['socket',self.arg(cpu.RDI),self.arg(cpu.RSI),self.arg(cpu.RDX)])
            result=self.plan['socket'];self.current_errno=self.plan['errno']
        elif name=='connect':
            fd=self.arg(cpu.RDI);address=self.get(cpu.RSI,64);length=self.get(cpu.RDX,32)
            need(length in (16,28) and address is not None,'unqualified sockaddr extent')
            raw=[self.load(address+i,1) for i in range(length)]
            need(all(byte is not None for byte in raw),'unknown byte in passed sockaddr')
            self.events.append(['connect',fd,bytes(raw).hex(),length])
            result=self.plan['connect'];self.current_errno=self.plan['errno']
        elif name=='__errno_location':
            self.events.append(['errno',self.current_errno])
            self.store(ERRNO,4,self.current_errno&0xffffffff);result=ERRNO;pointer=True
        else:
            self.events.append(['close',self.arg(cpu.RDI)])
            self.current_errno=self.plan['errno_after_close'];self.store(ERRNO,4,self.current_errno&0xffffffff)
            result=self.plan['close']
        for reg in cpu.CALLER_SAVED:
            self.put(reg,64,None)
        self.xmm=[None]*16;self.flags=[None]*4
        self.put(cpu.RAX,64 if pointer else 32,result if pointer else result&0xffffffff)
        if not pointer:self.known[cpu.RAX]=0xffffffff  # ABI defines the int result, not upper RAX.


def address(family,port):
    raw=bytearray(b'\xa5'*32);struct.pack_into('<H',raw,0,family)
    if family==0:
        raw[2:6]=bytes([127,(port>>8)&255,port&255,1]);struct.pack_into('<H',raw,6,port)
    else:
        raw[4:20]=bytes((i^(port&255)) for i in range(16))
        struct.pack_into('<IIH',raw,20,0x01020304^port,0x89abcdef^port,port)
    return bytes(raw)


def evaluate(image,raw,plan):
    need(len(raw)==32 and int.from_bytes(raw[:2],'little') in (0,1),'qualified address family required')
    m=Machine(image,plan);m.set_reg(cpu.RSP,cpu.STACK-8);m.store(cpu.STACK-8,8,cpu.RETURN_MARK)
    for reg in cpu.CALLEE_SAVED:
        m.set_reg(reg,0x1111111100000000+reg)
    saved=[m.get(reg,64) for reg in cpu.CALLEE_SAVED]
    m.set_reg(cpu.RDI,cpu.OUT);m.set_reg(cpu.RSI,cpu.INPUT)
    for index,byte in enumerate(raw):m.mem[cpu.INPUT+index]=byte
    for index in range(16):m.mem[cpu.OUT+index]=0xa5
    try:
        m.run(START)
    except cpu.Done as done:
        need(done.how=='ret','helper did not return normally')
    need(m.get(cpu.RAX,64)==cpu.OUT and m.get(cpu.RSP,64)==cpu.STACK,'return pointer/stack changed')
    need(saved==[m.get(reg,64) for reg in cpu.CALLEE_SAVED],'callee-saved register changed')
    output=bytes(m.load(cpu.OUT+index,1) for index in range(16))
    return {'events':m.events,'output_hex':output.hex(),
            'input_offsets_read':sorted(m.input_reads),'output_offsets_written':sorted(m.output_writes)},m.seen


def model(raw,plan):
    """Independent field/byte and signed-result equations, not instruction dispatch."""
    family=int.from_bytes(raw[:2],'little');events=[['socket',2+8*family,0x80801,0]]
    output=bytearray(b'\xa5'*16);fd=plan['socket'];errno=plan['errno']
    def finished():
        read=[0,1] if fd<0 else list(range(8)) if family==0 else [0,1]+list(range(4,30))
        writes=list(range(8)) if output[:4]==bytes(4) else list(range(4))+list(range(8,16))
        return {'events':events,'output_hex':output.hex(),'input_offsets_read':read,'output_offsets_written':writes}
    if fd>=0:
        if family==0:
            port=int.from_bytes(raw[6:8],'little')
            packed=b'\x02\0'+port.to_bytes(2,'big')+raw[2:6]+bytes(8)
        else:
            port=int.from_bytes(raw[28:30],'little')
            packed=b'\x0a\0'+port.to_bytes(2,'big')+raw[20:24]+raw[4:20]+raw[24:28]
        events.append(['connect',fd,packed.hex(),len(packed)])
        if plan['connect']>=0:
            struct.pack_into('<II',output,0,0,fd)
            return finished()
    events.append(['errno',errno])
    if fd>=0 and errno==115:
        struct.pack_into('<II',output,0,0,fd)
    else:
        struct.pack_into('<I',output,0,1)
        struct.pack_into('<Q',output,8,((errno&0xffffffff)<<32)|2)
        if fd>=0:events.append(['close',fd])
    return finished()


def cases():
    for family in (0,1):
        for port in (0,1,255,256,0x1234,65535):
            for fd in (-(1<<31),-1,0,7,(1<<31)-1):
                for connected in (-(1<<31),-1,0,1):
                    for errno in (-1,0,4,115,(1<<31)-1):
                        yield address(family,port),{'socket':fd,'connect':connected,'errno':errno,
                                                   'close':-1 if port&1 else 0,'errno_after_close':-999}


def analyse(binary=TARGET):
    data=Path(binary).read_bytes();image,record=inspect(data)
    results=[];seen=set()
    for index,(raw,plan) in enumerate(cases()):
        actual,visited=evaluate(image,raw,plan);expected=model(raw,plan)
        need(actual==expected,'independent connect model differs at case '+str(index))
        seen.update(visited)
        results.append({'id':index,'address_hex':raw.hex(),'plan':plan,**actual})
    linear={insn.va for insn in cpu.sweep(image,START,END)}
    need(seen==linear,'not every decoded helper instruction was exercised')
    return {'native':record,'case_count':len(results),'instruction_coverage':{'decoded':len(linear),'seen':len(seen)},
            'results':results,'authorized_offline_Python_instruction_evaluation':True,
            'native_capture_or_network_used':False,
            'limits':'Only immutable initialized family0/1 input, separated memory and normally returning SysV callbacks. No libc implementation, original Rust type/ABI, live connectivity or whole-node claim.'}


def controls(binary=TARGET):
    data=Path(binary).read_bytes();image,_=inspect(data)
    raw=address(0,0x1234)
    good={'socket':7,'connect':0,'errno':0,'close':-1,'errno_after_close':-999}
    pending=dict(good,connect=-1,errno=115)
    records=[]
    for name,va,value,plan in [('socket-type',0x3cd634d,2,good),
                              ('ipv4-port-rotation',0x3cd63a9,0,good),
                              ('in-progress-code',0x3cd63f1,114,pending)]:
        private=bytearray(data);private[image.file_offset(va)]=value
        before,_=evaluate(image,raw,plan);after,_=evaluate(cpu.Image(private),raw,plan)
        need(before!=after,'actual instruction mutation escaped full trace/result comparator')
        try:observe(private)
        except ValueError as error:rejected=str(error)
        else:raise ValueError('actual instruction mutation accepted by local admission')
        records.append({'name':name,'address':hex(va),'before':before,'after':after,'rejected':rejected,
                        'result_words_unchanged':before['output_hex']==after['output_hex']})
    return records


def corpus_bytes(result):
    return b''.join((json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode()
                    for row in result['results'])


def decoder_crosscheck(data):
    import capstone
    image,record=inspect(data)
    off=image.file_offset(START);raw=data[off:off+END-START]
    decoded=list(capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(raw,START))
    other=[(i.address,i.size,bytes(i.bytes).hex()) for i in decoded]
    own=[(i.va,i.size,bytes(data[i.off:i.off+i.size]).hex()) for i in cpu.sweep(image,START,END)]
    need(other==own and sum(row[1] for row in other)==247,'independent complete decode differs')
    return {'instructions':len(other),'complete_bytes':247,'raw_instruction_rows_equal':True}


def summary(result):
    return {**{k:v for k,v in result.items() if k!='results'},'corpus_sha256':sha(corpus_bytes(result)),
            'observed_ROL16_lowering':'Only count8 value relation; unused CF/OF unknown, zero-count preserves flags. Unknown flag use fails closed.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    need(not args.output.exists(),'output directory must be new')
    result=analyse(args.binary);args.output.mkdir(parents=True)
    (args.output/'records.json').write_text(json.dumps(summary(result),indent=2)+'\n')
    (args.output/'vectors.jsonl').write_bytes(corpus_bytes(result))
    (args.output/'controls.json').write_text(json.dumps(controls(args.binary),indent=2)+'\n')
    print(json.dumps({'cases':result['case_count'],'coverage':result['instruction_coverage']}))
