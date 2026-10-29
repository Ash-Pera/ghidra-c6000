#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Normal decompiler activation of owned call traces; IMAGE JSON [be].
Synthetic CALLP/branch/store fields: SPRUFE8B 3.5/3.7/4.2 and CALLP p.172.
The existing call fixture supplies both S units, compact headers and repeated calls.
"""
from pathlib import Path
import importlib.util,json,struct,sys

def main():
 image,manifest=map(Path,sys.argv[1:3]);big=len(sys.argv)>3;endian='>' if big else '<'
 spec=importlib.util.spec_from_file_location('calls',Path(__file__).with_name('pipeline-calls.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.main()
 rows=json.loads(manifest.read_text());chosen={'closed_s2_','closed_s1_peer_both','closed_s2_compact_rs','closed_s1_header_seam','multi_reuse','multi_distinct'};data=bytearray(image.read_bytes());out=[]
 for row in rows:
  if row['name'] not in chosen:continue
  if row['mode']=='closed':
   for site in row['sites']:
    # Return with a captured E3 store still in flight; the caller must mature it.
    side=1 if '_s1_' in row['name'] else 2
    words=[3<<18|0x362|(0x1000 if side==1 else 0),3<<13,6<<23|4<<18|0x274]
    for k,word in enumerate(words):struct.pack_into(endian+'I',data,site['callee']-0x1000+4*k,word)
    site['callee_return']=site['callee'];site['callee_end']=site['callee']+12
  if row['name']=='closed_s1_peer_both':row['entry_writes']=['B5','A5']
  row['memory_word']=0x12345678;out.append(row)
 assert len(out)==6
 image.write_bytes(data);manifest.write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
