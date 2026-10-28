#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic SPRUFE8B full32 alias/form cases. IMAGE CASES.tsv [be].

Opcodes are field compositions from the architecture maps, independently
cross-checked against the TI assembler during the roundtrip investigation.
"""
from pathlib import Path
import struct,sys

def main():
 image,manifest=map(Path,sys.argv[1:3]);endian='>' if len(sys.argv)>3 and sys.argv[3]=='be' else '<'
 image.parent.mkdir(parents=True,exist_ok=True);cases=[]
 # Exact scalar MV aliases: preserve their ADD/OR family in display.
 for family,unit,fixed in [('ADD','L',0x58),('OR','L',0xfd8),('ADD','S',0x1a0),('ADD','D',0x940),('OR','D',0x8f0)]:
  for side in [1,2]:
   for cross in ([False] if unit=='D' and family=='ADD' else [False,True]):
    for creg,z,predicate in [(0,0,0),(1,0,1),(1,0,0),(1,1,0),(1,1,1)]:
     bank='A' if side==1 else 'B';src=('B' if bank=='A' else 'A') if cross else bank
     word=fixed|((side-1)<<1)|(int(cross)<<12)|(3<<18)|(4<<23)|(creg<<29)|(z<<28)
     prefix='' if creg==0 else ('[!B0]' if z else '[B0]')
     mnemonic=prefix+family+'.'+unit+str(side)+('X' if cross else '')
     executes=creg==0 or (predicate==0 if z else predicate!=0)
     cases.append(dict(word=word,mnemonic=mnemonic,form='NONE',offset='-',base='-',scale='-',pc='-',header=0,kind='move',source=src+'3',destination=bank+'4',value=0x89abcdef if executes else 0x11223344,predicate=predicate))
 # ZERO must remain the actual SUB, including the real source index.
 for side in [1,2]:
  for unit,fixed in [('L',0xf8),('S',0x5e0),('D',0x8c0)]:
   bank='A' if side==1 else 'B';word=fixed|((side-1)<<1)|(1<<13)|(1<<18)|(4<<23)
   cases.append(dict(word=word,mnemonic='SUB.'+unit+str(side),form='NONE',offset='-',base='-',scale='-',pc='-',header=0,kind='zero',source=bank+'1',destination=bank+'4',value=0,predicate=0))
 # Same TI spelling and operands, distinct address forms.
 cases += [
  dict(word=0x1d40|2|(15<<18)|(12<<13)|(5<<23),mnemonic='ADDAW.D2',form='SHORT5',offset=12,base='B15',scale=4,pc='-',header=0,kind='metadata'),
  dict(word=0x1000007c|2|128|(12<<8)|(5<<23),mnemonic='ADDAW.D2',form='LONG15',offset=12,base='B15',scale=4,pc='-',header=0,kind='metadata'),
  dict(word=0x64|128|(1<<9)|(5<<13)|(14<<18)|(3<<23),mnemonic='LDW.D2',form='SHORT5',offset=5,base='B14',scale=4,pc='-',header=0,kind='metadata'),
  dict(word=0x6c|(5<<8)|(3<<23),mnemonic='LDW.D2',form='LONG15',offset=5,base='B14',scale=4,pc='-',header=0,kind='metadata'),
  dict(word=0x64|128|(5<<9)|(5<<13)|(14<<18)|(3<<23),mnemonic='LDW.D2',form='REGISTER',offset='-',base='B14',scale=4,pc='-',header=0,kind='metadata'),
  dict(word=0x418|(2<<18)|(4<<23),mnemonic='MV.L1',form='NONE',offset='-',base='-',scale='-',pc='-',header=0,kind='metadata'),
 ]
 # Header presence changes only full32 BNOP's displacement scale, even with
 # zero layout bits and BR=0. B/BDEC/BPOS retain their four-byte scale.
 for header in [0,0xe0000000]:
  for op,word,scale in [('BNOP',0xa120|(16<<16),2 if header else 4),('B',0x10|(16<<7),4),('BDEC',0x1020|(1<<23)|(16<<13),4),('BPOS',0x20|(1<<23)|(16<<13),4)]:
   cases.append(dict(word=word,mnemonic=op+'.S1',form='NONE',offset='-',base='-',scale='-',pc=scale,header=header,kind='metadata'))
 with image.open('wb') as b,manifest.open('w') as t:
  for index,c in enumerate(cases):
   b.write(struct.pack(endian+'I',c['word'])+bytes(24)+struct.pack(endian+'I',c['header']))
   fields=[index,c['mnemonic'],c['form'],c['offset'],c['base'],c['scale'],c['pc'],int(bool(c['header'])),c['kind'],c.get('source','-'),c.get('destination','-'),format(c.get('value',0),'x'),c.get('predicate',0)]
   t.write('\t'.join(map(str,fields))+'\n')
 print('cases',len(cases))
if __name__=='__main__':main()
