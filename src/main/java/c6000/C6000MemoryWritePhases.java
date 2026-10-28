// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.util.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/** LOAD data dependence through raw p-code, not a second address/load implementation.
 * SPRUFE8B 4.2.5/Table4-10: pointer modification writes E1, loaded data writes E5.
 */
final class C6000MemoryWritePhases {
    private record ByteKey(int space,long offset) {}
    private static boolean tainted(Varnode node,Set<ByteKey> state) {
        if(node.isConstant())return false;
        for(int k=0;k<node.getSize();k++)
            if(state.contains(new ByteKey(node.getAddress().getAddressSpace().getSpaceID(),node.getOffset()+k)))return true;
        return false;
    }
    static Set<Integer> loadWrites(PcodeOp[] code) {
        var states=new ArrayList<Set<ByteKey>>();
        for(int k=0;k<=code.length;k++)states.add(null);
        states.set(0,new HashSet<>());var queue=new ArrayDeque<Integer>();queue.add(0);
        var result=new HashSet<Integer>();
        while(!queue.isEmpty()) {
            int index=queue.removeFirst();if(index==code.length)continue;
            var op=code[index];var state=new HashSet<>(states.get(index));
            boolean loaded=op.getOpcode()==PcodeOp.LOAD;
            if(!loaded)for(var input:op.getInputs())loaded|=tainted(input,state);
            if(op.getOpcode()==PcodeOp.CBRANCH&&tainted(op.getInput(1),state))
                throw new IllegalArgumentException("load-dependent raw control flow has no E1/E5 write contract");
            var output=op.getOutput();
            if(output!=null) {
                int space=output.getAddress().getAddressSpace().getSpaceID();
                for(int k=0;k<output.getSize();k++) {
                    var key=new ByteKey(space,output.getOffset()+k);state.remove(key);
                    if(loaded)state.add(key);
                }
                if(output.isRegister()&&loaded)result.add(index);
            }
            var next=new ArrayList<Integer>();
            if(op.getOpcode()==PcodeOp.BRANCH||op.getOpcode()==PcodeOp.CBRANCH) {
                if(op.getInput(0).isConstant())next.add(index+(int)op.getInput(0).getOffset());
                if(op.getOpcode()==PcodeOp.CBRANCH)next.add(index+1);
            }else if(!Set.of(PcodeOp.BRANCHIND,PcodeOp.RETURN,PcodeOp.CALL,PcodeOp.CALLIND).contains(op.getOpcode()))next.add(index+1);
            for(int target:next) {
                if(target<0||target>code.length)throw new IllegalArgumentException("raw memory branch leaves instruction");
                var old=states.get(target);
                if(old==null){states.set(target,new HashSet<>(state));queue.add(target);}
                else if(old.addAll(state))queue.add(target);
            }
        }
        return Set.copyOf(result);
    }
}
