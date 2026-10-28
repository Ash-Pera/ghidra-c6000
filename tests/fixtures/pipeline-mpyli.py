#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""MPYLI E1 capture/E4 simultaneous pair write, SPRUFE8B pp344--345. IMAGE JSON [be]."""
from pathlib import Path
import json,struct,sys


def signed(value,bits):
    value &= (1<<bits)-1
    return value-(1<<bits) if value>>(bits-1) else value


def product(a,b):return (signed(a,16)*signed(b,32))&((1<<64)-1)
def op(a=2,b=3,d=4,side=1,cross=False,predicate=0):return (predicate<<29)|(d<<23)|(b<<18)|(a<<13)|(int(cross)<<12)|0x570|(2 if side==2 else 0)
def mv(src,dst,side=1,unit='L'):return (dst<<23)|(src<<18)|(0xfd8 if unit=='L' else 0x6a0)|(2 if side==2 else 0)
def mvk(value,dst,side=1):return (dst<<23)|((value&0xffff)<<7)|(0x28 if side==1 else 0x2a)


def main():
    endian='>' if len(sys.argv)>3 and sys.argv[3]=='be' else '<';image=bytearray(0x3000);rows=[]
    def emit(name,words,inputs,expected,raw_expected=None,refused=None):
        entry=0x1000+len(rows)*0x100
        for k,word in enumerate(words):struct.pack_into(endian+'I',image,entry-0x1000+4*k,word)
        row=dict(name=name,entry=entry,input=inputs,expected=expected,raw_expected=raw_expected or {})
        if refused:row['refused']=refused
        rows.append(row)
    def observed(name,a,b,side=1,src1=2,src2=None,dst=4,cross=False,predicate=0,enabled=True,companions=(),extra=None,known=None):
        bank='A' if side==1 else 'B';other='B' if side==1 else 'A';src2=(3 if side==1 else 6) if src2 is None else src2
        inputs={bank+str(src1):a,(other if cross else bank)+str(src2):b};inputs.update(extra or {})
        inputs.setdefault(bank+str(dst),0x11112222);inputs.setdefault(bank+str(dst+1),0x33334444)
        oldlow=inputs[bank+str(dst)];oldhigh=inputs[bank+str(dst+1)]
        value=product(a,b) if known is None else known;low=value&0xffffffff;high=value>>32
        if not enabled:low=oldlow;high=oldhigh
        first=[op(src1,src2,dst,side,cross,predicate),*companions];first=[w|(1 if k<len(first)-1 else 0) for k,w in enumerate(first)]
        words=first+[0x2000,mv(dst,20,side)|1,mv(dst+1,21,side,'S'),mv(dst,22,side)|1,mv(dst+1,23,side,'S'),0xc0362,0x8000]
        expected={bank+str(dst):low,bank+str(dst+1):high,bank+'20':oldlow,bank+'21':oldhigh,bank+'22':low,bank+'23':high}
        emit(name,words,inputs,expected,{bank+str(dst):low,bank+str(dst+1):high})
    for side in [1,2]:
        for k,(a,b) in enumerate([(0,0x80000000),(0x12348000,0x80000000),(0xffff7fff,0x80000000),(0xabcdffff,0x7fffffff)]):observed(f'edge_side{side}_{k}',a,b,side)
    observed('manual_example1',0x6a321193,0xb1746ca4,src1=5,src2=6,dst=8,known=0xfffffa9ba111462c)
    observed('manual_example2',0x12343497,0x21ff50a7,side=2,src1=2,src2=5,dst=8,known=0x000006fbe9fa7e81)
    for source in ['src1','src2']:
        for register in [4,5]:observed(f'alias_{source}_{register}',0x1234ffff,0x80000000,**{source:register})
    observed('crosspath_sources_captured',0x1234fffe,0x80000000,cross=True,src2=6,companions=[mv(7,2),mv(7,6,2)],extra={'A7':0,'B7':0})
    observed('true_predicate_captured',0x1234ffff,0x80000000,predicate=6,companions=[mvk(0,0)],extra={'A0':1})
    observed('false_predicate_captured',0x1234ffff,0x80000000,predicate=6,enabled=False,companions=[mvk(1,0)],extra={'A0':0})
    value=product(0xffff0003,0x7fffffff)
    emit('consecutive_m1_issues',[op(),op(6,7,12),0x2000,mv(4,20)|1,mv(5,21,unit='S'),mv(12,22)|1,mv(13,23,unit='S'),0xc0362,0x8000],
         {'A2':0xffff0003,'A3':0x7fffffff,'A6':2,'A7':3},
         {'A4':value&0xffffffff,'A5':value>>32,'A12':6,'A13':0,'A20':value&0xffffffff,'A21':value>>32,'A22':6,'A23':0},
         {'A4':value&0xffffffff,'A5':value>>32})
    inputs={'A2':2,'A3':3,'A6':2,'A7':3,'B6':2,'B7':3}
    mpy=(8<<23)|(7<<18)|(6<<13)|0xc80
    emit('same_unit_result_ports_refused',[op(),0,mpy,0,0xc0362,0x8000],inputs,refused='MPYLI result write-port conflict',expected={})
    emit('cross_unit_result_ports',[op(),0,mpy|2,0,mv(4,20)|1,mv(5,21,unit='S')|1,mv(8,24,2),0xc0362,0x8000],inputs,
         {'A4':6,'A5':0,'A20':6,'A21':0,'B8':6,'B24':6},{'A4':6,'A5':0})
    emit('same_ep_unit_refused',[op()|1,op(6,7,12),0xc0362,0x8000],inputs,refused='functional-unit collision',expected={})
    Path(sys.argv[1]).write_bytes(image);Path(sys.argv[2]).write_text(json.dumps(rows,indent=2)+'\n')


if __name__=='__main__':main()
