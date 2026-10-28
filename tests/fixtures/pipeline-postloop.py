#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SPRUFE8B 7.9.4/7.12 dispatch and 7.15.2 missed-stall cases.
IMAGE CASES.json [be]. TI_C6000_BIN selects cl6x/bin; .asm/.obj/.log
are retained beside IMAGE. No firmware inputs. Ordinary instructions use TI
.nocmp; raw loop starts deliberately bypass assembler checks in negative cases.
"""
from pathlib import Path
import json,os,struct,subprocess,sys

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
    image_path,manifest_path=map(Path,sys.argv[1:3]);image_path.parent.mkdir(parents=True,exist_ok=True)
    sections=[];rows=[]
    def case(name,lines,inputs,expected,**extra):
        entry=0x1000+len(rows)*0x200
        sections.extend([' .sect ".ct_'+name+'"',' .nocmp',*[line if line.endswith(':') else ' '+line for line in lines]])
        rows.append(dict(name=name,entry=entry,input=inputs,expected=expected,**extra))
    for count,delay in [(3,0),(3,1),(3,5),(3,20),(0,0),(1,0)]:
        # II6/dynlen13. Count3 terminates at E1 cycle18; drain starts19.
        # SPKERNEL delay is capped at dynlen-II=7. Zero/one retain the
        # final loading-stage boundary at18 (7.9.5), then dispatch at19.
        first=19+(min(delay,7) if count==3 else 0)
        observed=0 if count==0 else 1 if count==1 or delay==0 else 3 if delay>=7 else 2
        body=['SPLOOP 6','ADD.L1 A4,1,A4']+['NOP']*11+['SPKERNEL '+str(delay//6)+','+str(delay%6),'|| ADD.L2 B5,1,B5']
        case('normal_'+str(count)+'_delay_'+str(delay),body+['OR.S2 B5,0,B12','MVK.S1 17,A20','NOP 7','NOP 7','B.S2 B3','NOP 5'],{'ILC':count},{'A4':count,'B5':count,'B12':observed,'A20':17,'TSR':0},expected_first_marker_cycle=first+1,expected_cycles=first+22,cycle_basis='7.9.4: first post packet at drain start+min(delay,dynlen-II); marker is next packet')
    for inverse in [None,0,1]:
        read='OR.L2X A4,0,B5' if inverse is None else '[!A0] OR.L2X A4,0,B5'
        write='MVK.S1 7,A4' if inverse is None else '[A0] MVK.S1 7,A4'
        kw={'refused':'missed X-path/AMR stall'} if inverse is None else {}
        case('buffered_x_'+('required' if inverse is None else 'complement_'+str(inverse)),['.word 0x00838000',read,write,'NOP','NOP','.word 0x00034000','NOP 8','B.S2 B3','NOP 5'],{'ILC':3,'A4':3,'A0':inverse or 0},{'B5':3 if inverse==0 else 0,'A4':3 if inverse==0 else 7},**kw)
    case('buffered_amr_required',['.word 0x00838000','LDW.D1 *A4,A6','SPMASK S2','|| MVC.S2 B0,AMR','NOP','NOP','.word 0x00034000','NOP 8','B.S2 B3','NOP 5'],{'ILC':3,'A4':0x8000,'B0':1},{},refused='missed X-path/AMR stall')
    case('buffered_late_predicate_changed',['MVK.S1 1,A0','.word 0x01838000','[A0] ADDDP.L2X B9:B8,A5:A4,B11:B10','NOP','NOP','NOP','MVK.L1 3,A5','|| MVK.S1 0,A0','NOP','NOP','NOP','.word 0x00034000','NOP 8','B.S2 B3','NOP 5'],{'ILC':3},{},refused='buffered late port')
    case('buffered_final_write_changes_predicate',['MVK.S1 1,A0','MPYSP.M1 A6,A7,A0','.word 0x0083a000','[!A0] OR.L2X A4,0,B5','[A0] MVK.S1 7,A4','NOP','NOP','.word 0x00034000','NOP 8','B.S2 B3','NOP 5'],{'ILC':3,'A6':0,'A7':0},{},refused='missed X-path/AMR stall')
    case('pm_pair_x_stalls',['MVK.S1 0,A4','ADDDP.L2X B9:B8,A5:A4,B11:B10','NOP 7','B.S2 B3','NOP 5'],{'A5':0x3ff00000,'B9':0x40000000},{'B10':0,'B11':0x40080000},expected_cycles=16,expected_stalls=1)
    case('pm_x_stalls',['MVK.S1 7,A4','OR.L2X A4,0,B5','NOP 4','B.S2 B3','NOP 5'],{}, {'B5':7},expected_cycles=13,expected_stalls=1)
    case('pm_amr_stalls',['MVC.S2 B0,AMR','LDW.D1 *A4,A6','NOP 5','B.S2 B3','NOP 5'],{'B0':1,'A4':0x8000},{'A6':23},memory={'32768':23},expected_cycles=14,expected_stalls=1)
    for bypass in [False,True]:
        name='suffix_'+('bypass_refuses_proof' if bypass else 'dominated_constant')
        tag='sf_'+name
        head=[('[A0] B.S1 '+tag+'_loop') if bypass else ('B.S1 '+tag+'_anchor'),'NOP 5',tag+'_anchor:','NOP 8','MVK.S2 186,B4','ADD.S2 B4,-1,B4',tag+'_loop:','SPLOOPD 6','|| MVC.S2 B4,ILC']
        body=['ADD.L1 A4,1,A4']+['NOP']*11+['SPKERNEL 0,0','|| ADD.L2 B5,1,B5','NOP 8','B.S2 B3','NOP 5']
        # Five full32 words precede the start packet; labels have zero width.
        case(name,head+body,{}, {},proof_only=True,proof_loop=0x1000+len(rows)*0x200+20,proof_counter=None if bypass else 185)
    first=['MVK.S2 9,B4','MVC.S2 B4,ILC','NOP 3','SPLOOP 6','ADD.L1 A4,1,A4']+['NOP']*11+['SPKERNEL 0,0','|| ADD.L2 B5,1,B5','B.S1 sf_short_second','NOP 5']+['NOP 8']*8+['sf_short_second:','B.S1 sf_short_anchor','NOP 5','sf_short_anchor:','NOP 8','MVK.S2 186,B4','ADD.S2 B4,-1,B4']
    at=0x1000+len(rows)*0x200+4*sum(not line.endswith(':') for line in first)
    tail=['SPLOOPD 6','|| MVC.S2 B4,ILC','ADD.L1 A4,1,A4']+['NOP']*11+['SPKERNEL 0,0','|| ADD.L2 B5,1,B5','NOP 8','B.S2 B3','NOP 5']
    case('suffix_short_cfg_path_refuses_proof',first+tail,{}, {},proof_only=True,proof_loop=at,proof_counter=None)
    # MVC is explicitly SPMASKed above; these raw SPLOOP bits select II2.
    assembly=image_path.with_suffix('.postloop.asm');obj=image_path.with_suffix('.postloop.obj');log=image_path.with_suffix('.postloop.log');assembly.write_text('\n'.join(sections)+'\n')
    binary=Path(os.environ.get('TI_C6000_BIN','/Applications/ti/ti-cgt-c6000_8.3.15/bin'));compiler=binary/'cl6x' if binary.is_dir() else binary
    done=subprocess.run([str(compiler),'-mv6740','--abi=eabi','-c',str(assembly),'--output_file='+str(obj)],capture_output=True,text=True);log.write_text(done.stdout+done.stderr)
    if done.returncode:raise RuntimeError('TI assembly failed: '+str(log))
    data=object_sections(obj);image=bytearray(len(rows)*0x200)
    for index,row in enumerate(rows):
        code=data['.ct_'+row['name']]
        if len(code)>0x100 or len(code)%4:raise ValueError('Invalid section width')
        image[index*0x200:index*0x200+len(code)]=code
    if len(sys.argv)>3 and sys.argv[3]=='be':image=b''.join(image[k:k+4][::-1] for k in range(0,len(image),4))
    image_path.write_bytes(image);manifest_path.write_text(json.dumps(rows,indent=2)+'\n');print('POSTLOOP_FIXTURE_OK cases='+str(len(rows)))
if __name__=='__main__':main()
