#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retimed DP arithmetic using the existing exact-rational oracle. IMAGE CASES.json [be]."""
from pathlib import Path
import importlib.util, json, struct, sys
sys.dont_write_bytecode=True


def main():
    root=Path(__file__).parent;spec=importlib.util.spec_from_file_location('dp_oracle',root/'float-dp-arithmetic.py');oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
    cases=[];image=bytearray();endian='>' if len(sys.argv)>3 and sys.argv[3]=='be' else '<'
    # Only the .S 1110111 form reverses subtraction; .L 0011101 selects src1 X.
    forms=[('ADDDP','L',1,False,'0011000'),('ADDDP','S',2,False,'1110010'),('SUBDP','L',1,False,'0011001'),('SUBDP','L',2,False,'0011101'),('SUBDP','S',1,True,'1110111'),('MPYDP','M',1,False,''),('MPYDP','M',2,False,'')]
    for name,unit,side,reverse,field in forms:
        bank='A' if side==1 else 'B';shift=0 if side==1 else 16;control='FMCR' if name=='MPYDP' else 'FADCR';control_number=20 if name=='MPYDP' else 18
        # B7 carries a new status value (including a different rounding mode)
        # written only after all multiply source ports have been sampled.
        for mode in range(4):
            selected=(oracle.MUL_CASES if name=='MPYDP' else oracle.ADD_CASES)[:16]
            for number,(left,right) in enumerate(selected):
                output,flags=oracle.multiply(left,right,mode) if name=='MPYDP' else oracle.addsub(left,right,mode,name=='SUBDP',reverse)
                opcode=oracle.opcode(name,unit,side,field)
                if number%2==0:opcode=(opcode&~(31<<23)) # output aliases source pair 0
                destination=0 if number%2==0 else 4
                preset=(mode<<(9+shift))|(0xc0<<shift);new_status=0x10000 if side==1 else 1
                words=[opcode,0x4000,(control_number<<23)|(7<<18)|0x3a2,0x10000,(3<<23)|(31<<18)|0x105a,0xc0362,0x8000]
                index=len(cases);image.extend(struct.pack(endian+'7I',*words)+bytes(64-28))
                inputs={bank+'0':left&0xffffffff,bank+'1':left>>32,bank+'2':right&0xffffffff,bank+'3':right>>32,control:preset,'B7':new_status,'A31':0x9000}
                expected={bank+str(destination):output&0xffffffff,bank+str(destination+1):output>>32,control:new_status|(flags<<shift),'PC':0x9000}
                cases.append(dict(name=f'{name}_{unit}{side}_r{mode}_{number}',entry=0x1000+64*index,input=inputs,expected=expected,extent=63))
    Path(sys.argv[1]).write_bytes(image);Path(sys.argv[2]).write_text(json.dumps(cases,indent=2))


if __name__=='__main__':main()
