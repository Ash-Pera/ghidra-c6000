// SPDX-License-Identifier: Apache-2.0
package c6000;
import java.io.IOException;
import java.util.Arrays;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
public class C6000PipelinePayload extends InjectPayloadCallother {

    public C6000PipelinePayload(String source){
        super(source);
    }
    @Override public boolean isFallThru(){
        return true;
    }
    @Override public PcodeOp[] getPcode(Program program,InjectContext context)throws IOException {
        var f=program.getFunctionManager().getFunctionAt(context.baseAddr);
        if(f==null)throw new IOException("Scheduled entry has no owning function: "+context.baseAddr);
        if(program.getOptions(C6000PipelineSchedules.OPTIONS).getString(C6000PipelineSchedules.contractKey(f), "").isBlank())throw new IOException("Scheduled entry lacks a drained-pipeline contract: "+context.baseAddr);
        var hazards=program.getOptions(C6000PipelineSchedules.OPTIONS).getString(C6000PipelineSchedules.hazardsKey(f), "");
        var writes=hazards.isEmpty()?java.util.Set.<String>of():java.util.Set.of(hazards.split(","));
        try{
            var result=C6000PipelineSchedules.compileConfigured(program,f,writes);
            C6000PipelineContracts.validate(program,f,result,ghidra.util.task.TaskMonitor.DUMMY);
            var ops=Arrays.copyOf(result.code(),result.code().length);
            var ret=program.getRegister("C6000_PIPE_RET");
            var value=new Varnode(ret.getAddress(),4);
            ops[ops.length-1]=new PcodeOp(context.baseAddr,ops.length-1,PcodeOp.COPY,new Varnode[]{
                value
            }
            ,value);
            return ops;
        }
        catch(Exception e){
            throw new IOException("Exact C6000 schedule failed: "+e.getMessage(),e);
        }
    }
}
