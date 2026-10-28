#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stock-free closed caller traces: IMAGE CASES.json [be].

TI_C6000_BIN names the TI C6000 bin directory or cl6x executable; otherwise
use /Applications/ti/ti-cgt-c6000_8.3.15/bin. Retain source/object/log beside
IMAGE. All instructions use .nocmp; BE changes fullword byte order only.
"""
from pathlib import Path
import json
import os
import struct
import subprocess
import sys

specs=[('captured_old_B4','NOP','ADDAD.D2 B10,B10,B4',True,''),('caller_load_order','LDW.D1 *A4,A6','NOP 4',True,''),('caller_store_order','STW.D1 A7,*A4[0]','NOP 2',True,''),('captured_old_base','ADDK.S1 8,A4','NOP',True,''),('bad_hash','NOP','NOP',False,'byte hash mismatch'),('unowned_caller','NOP','NOP',False,'unowned code'),('conflicting_owner','NOP','NOP',False,'conflicting ownership'),('B3_writer','NOP','NOP',False,'unchanged entry B3'),('conditional_B3_writer','NOP','NOP',False,'unchanged entry B3'),('unknown_return_target','NOP','NOP',False,'unresolved register branch'),('insufficient_drain','NOP','NOP',False,'endpoint still has pending'),('nonstore_tail','NOP','NOP',False,'only captured STW'),('caller_branch','B.S2 B3','NOP 5',False,'straight-line'),('conditional_caller','[A0] MVK.S1 0,A0','NOP',False,'straight-line'),('entry_not_drained','NOP','NOP',False,'drained entry'),('hazard_mismatch','NOP','NOP',False,'hazard contract differs'),('out_of_plan_packet','NOP','NOP',False,'exact and contiguous'),('foreign_callee','NOP','NOP',False,'another function'),('header_context','NOP','NOP',False,'headerless full32'),('updating_store_tails','NOP','NOP',True,''),('captured_store_predicate','MVK.S1 0,A0','NOP',True,'')]

def object_sections(path):
    """Read bounded TI ELF32 sections and reject unresolved opcode relocations."""
    raw = path.read_bytes()
    if len(raw) < 52 or raw[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('Expected little-endian ELF32')
    header = struct.unpack_from('<16sHHIIIIIHHHHHH', raw)
    offset, stride, count, names_index = header[6], header[11], header[12], header[13]
    if header[1] != 1 or header[2] != 140:
        raise ValueError('Expected relocatable EM_TI_C6000 object')
    if stride != 40 or not 0 < names_index < count or offset + count * stride > len(raw):
        raise ValueError('Invalid ELF section table')
    rows = [struct.unpack_from('<10I', raw, offset + stride * index) for index in range(count)]
    for row in rows:
        if row[1] != 8 and row[4] + row[5] > len(raw):
            raise ValueError('ELF section outside object')
    def data(index):
        row = rows[index]
        return raw[row[4]:row[4] + row[5]]
    names = data(names_index)
    section_names = []
    for index, row in enumerate(rows):
        end = names.find(b'\0', row[0])
        if not 0 <= row[0] <= end:
            raise ValueError('Invalid ELF section name')
        section_names.append(names[row[0]:end].decode('utf-8'))
    sections = {}
    for index, row in enumerate(rows):
        name = section_names[index]
        if name.startswith('.ct_'):
            if name in sections:
                raise ValueError('Duplicate fixture section name')
            sections[name] = data(index)
        if row[1] in (4, 9):
            size = 12 if row[1] == 4 else 8
            if row[9] != size or row[5] % size or not 0 < row[7] < count:
                raise ValueError('Invalid ELF relocation section')
            # TI permits repeated debug section names and their relocations;
            # only instruction-bearing fixture sections feed this image.
            if not section_names[row[7]].startswith('.ct_'):
                continue
            for place in range(row[4], row[4] + row[5], size):
                location, info = struct.unpack_from('<II', raw, place)
                if location >= rows[row[7]][5] or (info & 255) not in (0, 254, 255):
                    raise ValueError('Unresolved opcode relocation')
    return sections


def main():
    if len(sys.argv) not in (3,4) or len(sys.argv)==4 and sys.argv[3]!='be':
        raise SystemExit('Usage: pipeline-caller-continuation.py IMAGE CASES.json [be]')
    image_path, manifest_path = map(Path,sys.argv[1:3])
    image_path.parent.mkdir(parents=True,exist_ok=True)
    manifest_path.parent.mkdir(parents=True,exist_ok=True)
    prefix=image_path.parent/(image_path.stem+'.caller-continuation')
    assembly, obj, log=(Path(str(prefix)+suffix) for suffix in ('.asm','.obj','.log'))
    lines=[];manifest=[]
    for i,(name,first,second,accepted,error) in enumerate(specs):
     tag='ct_'+name;lines+=[' .sect ".'+tag+'_callee"',' .nocmp',tag+'_callee:']
     if name=='B3_writer':lines+=[' MVK.S2 1,B3']
     if name=='conditional_B3_writer':lines+=[' [A0] MVK.S2 1,B3']
     if name=='foreign_callee':lines+=[' B.S1 '+tag+'_foreign',' NOP 5',' .align 512',tag+'_foreign:',' B.S2 B3',' NOP 5']
     elif name=='updating_store_tails':lines+=[' B.S2 B3',' NOP 3',' STW.D1 B5,*A4++[1]',' STW.D1 B4,*A4++[1]']
     elif name=='captured_store_predicate':lines+=[' B.S2 B3',' NOP 3',' [A0] STW.D1 B5,*A4[0]',' [!A0] STW.D1 B4,*A4[1]']
     elif name=='nonstore_tail':lines+=[' B.S2 B3',' NOP 3',' MPYSP.M1 A8,A9,A0',' NOP']
     else:lines+=[' B.S2 '+('A3' if name=='unknown_return_target' else 'B3'),' NOP 3',' STW.D1 B5,*A4[0]',' STW.D1 B4,*A4[1]']
     lines+=[' .sect ".'+tag+'_caller"',' .nocmp',tag+'_caller:',' '+first,' '+second]
     manifest.append(dict(name=name,at=0x1000+i*1024,caller=0x1100+i*1024,accepted=accepted,error=error))
    assembly.write_text('\n'.join(lines)+'\n')
    binary=Path(os.environ.get('TI_C6000_BIN','/Applications/ti/ti-cgt-c6000_8.3.15/bin'))
    compiler=binary/'cl6x' if binary.is_dir() else binary
    args=[str(compiler),'-mv6740','--abi=eabi','-c',str(assembly),'--output_file='+str(obj)]
    completed=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    log.write_text(completed.stdout)
    if completed.returncode:
        raise RuntimeError('TI assembly failed; see '+str(log))
    sections=object_sections(obj)
    image=bytearray(len(specs)*1024)
    for index,item in enumerate(manifest):
        for kind,offset in [('callee',0),('caller',256)]:
            data=sections['.ct_'+item['name']+'_'+kind]
            if len(data)>(768 if kind=='callee' else 256) or len(data)%4:
                raise ValueError('Invalid full32 fixture section size')
            image[index*1024+offset:index*1024+offset+len(data)]=data
        if item['name']=='header_context':
            # The reserved fetch-header marker proves this caller context is
            # outside v1's headerless contract; no instruction opcode is patched.
            struct.pack_into('<I',image,index*1024+256+28,0xe0000000)
    if len(sys.argv)==4:
        image=b''.join(image[index:index+4][::-1] for index in range(0,len(image),4))
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
    print('CALLER_CONTINUATION_FIXTURE_OK cases='+str(len(manifest)))


if __name__=='__main__':
    main()
