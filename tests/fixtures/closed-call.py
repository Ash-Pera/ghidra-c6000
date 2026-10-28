#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One closed B/ADDKPC call with late MPYLI/STW return tail; IMAGE JSON [le|be]."""
from pathlib import Path
import json,struct,sys

def mv(a,d,side=1,cross=False):return d<<23|a<<18|0xfd8|(2 if side==2 else 0)|(0x1000 if cross else 0)
def branch(pc,target):return 0x10|((((target-(pc&~31))>>2)&0x1fffff)<<7)
def link(pc,target):return 3<<23|((((target-(pc&~31))>>2)&0x7f)<<16)|0x162

def main():
    endian='>' if len(sys.argv)>3 and sys.argv[3]=='be' else '<';image=bytearray(0xc000);rows=[]
    specs=[('late_mpyli',None),('captured_store',None),('bad_hash','byte hash mismatch'),('callee_B3_writer','callee changes B3'),('unknown_link','link lacks exact'),('wrong_link','link lacks exact'),('unplanned_branch','undeclared control edge'),('not_drained','explicit drained entry'),('wrong_owner','language/owner identity mismatch'),('bad_stop','endpoint still has pending effects'),('declared_unowned_tail',None),('missing_unowned_span','flow leaves declared ownership'),('claimed_gap_has_owner','unowned span overlaps an owner'),('owned_body_mid_instruction','byte ownership'),('span_starts_mid_instruction','unowned span cuts an instruction'),('data_in_instruction_suffix','instruction overlaps defined data'),('header_start','invalid physical instruction start'),('full32_halfword_start','invalid physical instruction start'),('straddling_return_target','branch-target execute packet spans fetch packets'),('stale_compact_context',None),('header_eight_instruction_ep','eight-instruction header-based execute packet')]
    for index,(name,error) in enumerate(specs):
        c=0x1000+index*0x800+(4 if name=='captured_store' else 0);f=c+0x200;continuation=c+0x1c
        words=[3<<23|15<<18|1<<13|10<<9|0xf6,branch(c+4,f),0,0,0,0,link(c+0x18,continuation),mv(4,8),0,0,mv(4,9),3<<23|15<<18|1<<13|9<<9|0xe6,0x6000,0x8ca362]
        callee=[mv(3,1,cross=True),0x8c0362,0,0,0,0,4<<23|3<<18|2<<13|0x570]
        if name in ['captured_store','straddling_return_target']:
            callee[-1]=4<<23|6<<18|0x74|2 # STW .D1T2 B4,*A6[0]
            words[7]=mv(7,4,2)|1;words[8]=mv(7,6) # same EP source/base clobber, nextpc+0x24
        if name=='callee_B3_writer':callee[0]=mv(2,3,2)
        if name=='unknown_link':words[6]=mv(2,3,2)
        if name=='wrong_link':words[6]=link(c+0x18,continuation+4)
        if name=='unplanned_branch':callee[3]=branch(f+12,f+0x80)
        if name=='header_start':words[1]=branch(c+4,f+0x1c)
        if name=='full32_halfword_start':words[1]=branch(c+4,f) # plan alone is malformed below
        for k,word in enumerate(words):struct.pack_into(endian+'I',image,c-0x1000+k*4,word)
        for k,word in enumerate(callee):struct.pack_into(endian+'I',image,f-0x1000+k*4,word)
        row=dict(name=name,caller=c,caller_end=c+len(words)*4,callee=f,callee_end=f+len(callee)*4,call=c+4,link=c+0x18,continuation=continuation,callee_return=f+4,caller_return=c+0x34)
        if name=='header_eight_instruction_ep':
            struct.pack_into(endian+'HH',image,f-0x1000,0x0c6e,0x0c6e)
            for k in range(1,7):struct.pack_into(endian+'I',image,f-0x1000+4*k,1 if k<6 else 0)
            struct.pack_into(endian+'I',image,f-0x1000+28,0xe0200003)
            struct.pack_into(endian+'I',image,f-0x1000+32,0x8ca362)
            row.update(callee_end=f+0x24,callee_return=f+0x20)
        if name=='stale_compact_context':
            struct.pack_into(endian+'HH',image,f-0x1000,(5<<13)|0x1866|(6<<7),0x0c6e)
            for k,word in enumerate([mv(3,1,cross=True),0x8c0362,0,0,0,0]):struct.pack_into(endian+'I',image,f-0x1000+4+4*k,word)
            struct.pack_into(endian+'I',image,f-0x1000+28,0xe0200000)
            struct.pack_into(endian+'I',image,f-0x1000+32,4<<23|3<<18|2<<13|0x570)
            row.update(callee_end=f+0x24,callee_return=f+8)
        if name=='header_start':
            struct.pack_into(endian+'I',image,f-0x1000+0x1c,0xe0000000)
            struct.pack_into(endian+'I',image,f-0x1000+0x20,0x8ca362)
            row.update(callee=f+0x1c,callee_end=f+0x24,callee_return=f+0x20)
        if name=='full32_halfword_start':row.update(callee=f+2,callee_end=f+0x1c,callee_return=f+4)
        if name=='bad_stop':row['caller_end']=c+0x20
        if error:row['refused']=error
        rows.append(row)
    Path(sys.argv[1]).write_bytes(image);Path(sys.argv[2]).write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
