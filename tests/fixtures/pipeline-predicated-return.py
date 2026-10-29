#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Predicated full32 B.S2 register returns, SPRUFE8B B/register and 4.2.6.
IMAGE CASES.json [be]. Independent manual fields, no firmware bytes.
"""
from pathlib import Path
import json,struct,sys

def main():
 endian='>' if len(sys.argv)>3 else '<';rows=[];image=bytearray(0x8000)
 predicates=[('B0',1),('B1',2),('B2',3),('A1',4),('A2',5),('A0',6)]
 for preg,creg in predicates:
  for invert in (0,1):
   for truth in (0,1,0xffffffff):
    for writer in ('none','predicate','target'):
     taken=(truth==0) if invert else truth!=0
     entry=0x1000+len(rows)*0x100;words=[creg<<29|invert<<28|3<<18|0x362]
     inputs={'B3':0x9000,'A4':0x8000,'A6':0x12345678,'A7':0x9a,'A8':0,preg:truth}
     expected={preg:truth,'B3':0x9000,'A4':0x8000,'A8':0 if taken else 0x55,'PC':0x9000}
     if writer!='none':
      words[0]|=1
      side=1 if writer=='target' else int(preg[0]=='B');dst=3 if writer=='target' else int(preg[1]);value=0xa000 if writer=='target' else int(truth==0)
      inputs['AB'[side]+'9']=value;expected['B3' if writer=='target' else preg]=value
      words.append(dst<<23|9<<18|0xfd8|side<<1)
      if writer=='target' and not taken:expected['PC']=0xa000
     words += [2<<13,6<<23|4<<18|0x274,7<<23|4<<18|4<<13|0x234,
               8<<23|0x55<<7|0x28,0x008ca362]
     for i,w in enumerate(words):struct.pack_into(endian+'I',image,entry-0x1000+4*i,w)
     rows.append(dict(name=f'{preg}_z{invert}_{truth:x}_{writer}',entry=entry,input=inputs,expected=expected,taken=taken))
 # Full32 target registers other than B3 remain unresolved for the scheduler.
 for cross,reg in [(0,4),(1,3)]:
  entry=0x1000+len(rows)*0x100
  struct.pack_into(endian+'III',image,entry-0x1000,3<<29|reg<<18|cross<<12|0x362,4<<13,0x008ca362)
  rows.append(dict(name=f'unresolved_x{cross}',entry=entry,refused='unresolved register branch'))
 assert len(rows)==110
 Path(sys.argv[1]).write_bytes(image);Path(sys.argv[2]).write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
