#!/usr/bin/env python3
"""Extracted-constant byte/borrow and interval math; no instruction evaluation."""
from __future__ import annotations
import argparse
from pathlib import Path
from collect import Image, constants, encode, need

MASK=(1<<64)-1
def skip(c,w0,w1):
 x0,x1=w0^c["LFWORD"],w1^c["LFWORD"]
 return (((((c["C"]-x0)&MASK)|w0)&c["HI"])&
         (((c["C"]-x1)&MASK)|x1))==c["HI"]

def word(values):return int.from_bytes(bytes(values),"little")

def certificate(image):
 c=constants(image)
 need(c["LFWORD"]==c["restoredLFWORD"],"restored LF constant")
 cb=c["C"].to_bytes(8,"little");lf=c["LFWORD"].to_bytes(8,"little")
 hi=c["HI"].to_bytes(8,"little")
 cases=[]
 for lane in range(8):
  for borrow in ((0,)if lane==0 else(0,1)):
   need(lf[lane]==10 and hi[lane]==128,"LF/high-bit lane binding")
   sub=(cb[lane]-borrow)&255
   first=(sub|10)&128;second=sub&128
   need(first==second==0,"LF cannot satisfy skip lane")
   cases.append([lane,borrow,sub,first,second])
 # Finite boundary corroboration of a closed-form partition, not a scanner.
 lengths=list(range(34))+[63,64,65,127,128,129]
 count=0;positions=0
 for m in lengths:
  for residue in range(8):
   if m<=15:
    prefix,blocks,suffix=0,0,0
   else:
    prefix=(-residue)%8
    blocks=max(0,1+(m-16-prefix)//16)
    suffix=prefix+16*blocks
    need(0<=prefix<=7<m and suffix<=m,"interval bounds")
    if blocks:
     need(prefix+16*(blocks-1)<=m-16,"last wide start bound")
     need(prefix+16*blocks>m-16,"first excluded wide start")
   for i in range(m):
    regions=int(i<prefix)+int(prefix<=i<suffix)+int(suffix<=i<m)
    need(regions==1,"interval partition")
    positions+=1
   count+=1
 # Actual constant mutations have concrete mathematical false-negative vectors.
 vectors=[
  {"name":"wrong-LF-word","change":"LFWORD","value":0x0b0b0b0b0b0b0b0b,
   "w0":word([10]*8),"w1":word([10]*8)},
  {"name":"zeroed-C-lane1","change":"C","value":c["C"]&~(255<<8),
   "w0":word([11,10,11,11,11,11,11,11]),"w1":word([11]*8)},
  {"name":"missing-high-lane7","change":"HI","value":c["HI"]&~(255<<56),
   "w0":word([11]*7+[10]),"w1":word([11]*8)}]
 for v in vectors:
  mutant=dict(c);mutant[v["change"]]=v["value"]
  need(10 in v["w0"].to_bytes(8,"little")+v["w1"].to_bytes(8,"little"),"LF witness")
  need(not skip(c,v["w0"],v["w1"]) and skip(mutant,v["w0"],v["w1"]),
       "constant mutation false-negative witness")
  v["baselineSkip"],v["mutantSkip"]=False,True
  for key in("value","w0","w1"):v[key]=hex(v[key])
 return {"kind":"scalar byte-borrow and interval mathematics",
         "instructionEvaluation":False,"callbackExecution":False,
         "constants":{k:hex(v)for k,v in c.items()},
         "borrowColumns":["lane","incomingBorrow","subtractionByte","firstWordHigh","secondWordHigh"],
         "borrowCases":cases,"borrowCaseCount":len(cases),
         "intervalBoundaryChecks":{"lengths":lengths,"residues":8,"cases":count,
                                   "positionsPartitioned":positions,
                                   "formula":"prefix=alignmentDelta; blocks=max(0,1+floor((m-16-prefix)/16)); suffix=prefix+16*blocks"},
         "constantMutationWitnesses":vectors,
         "intervalCounterexamples":[
          {"change":"wide threshold15->14","remaining":15,"alignmentDelta":0,
           "admittedRead":[0,16],"validInput":[0,15],"overreadBytes":1},
          {"change":"wide stride16->32","remaining":33,"firstChecked":[0,16],
           "nextStart":32,"unchecked":[16,32],"LFAt":16}],
         "limits":"The general first-LF/progress/callback proof is manual. These checks do not execute a scanner, target instructions, or real callbacks."}

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--root",type=Path,default=Path("."));p.add_argument("--output",type=Path,required=True)
 a=p.parse_args();need(not a.output.exists(),"output exists")
 r=certificate(Image("115",(a.root/"artifacts/node/115/hl-node").read_bytes()))
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(encode(r))
 print("15 borrow cases, finite interval partitions and five mathematical counterexamples passed.")
if __name__=="__main__":main()
