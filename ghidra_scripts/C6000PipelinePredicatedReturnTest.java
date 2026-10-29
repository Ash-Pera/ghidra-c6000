// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B B/register and 4.2.6: E1 predicate/target capture before delay work.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.pcode.exec.*;
import java.nio.file.*;
import java.math.BigInteger;
import java.util.*;
import com.google.gson.*;
import c6000.*;

public class C6000PipelinePredicatedReturnTest extends GhidraScript {
    BytesPcodeArithmetic arithmetic;
    void equal(Object expected,Object actual,String why){if(!Objects.equals(expected,actual))throw new AssertionError(why+" expected="+expected+" actual="+actual);}
    BytesPcodeExecutorState initial(JsonObject row){var s=new BytesPcodeExecutorState(currentProgram.getLanguage(),PcodeStateCallbacks.NONE);for(var r:currentProgram.getLanguage().getRegisters())if(!r.isProcessorContext()&&r.getMinimumByteSize()==4)s.setVar(r,arithmetic.fromConst(0,4));if(row.has("input"))for(var x:row.getAsJsonObject("input").entrySet())s.setVar(currentProgram.getRegister(x.getKey()),arithmetic.fromConst(x.getValue().getAsLong(),4));byte[] ram=new byte[16];Arrays.fill(ram,(byte)0x5a);s.setVar(toAddr(0x8000),16,false,ram);return s;}
    long value(BytesPcodeExecutorState s,String name){return arithmetic.toLong(s.getVar(currentProgram.getRegister(name),PcodeExecutorStatePiece.Reason.INSPECT),PcodeArithmetic.Purpose.INSPECT);}
    void execute(PcodeOp[] code,BytesPcodeExecutorState s){var language=(SleighLanguage)currentProgram.getLanguage();var lib=PcodeUseropLibrary.<byte[]>nil();var e=new PcodeExecutor<byte[]>(language,arithmetic,s,PcodeExecutorStatePiece.Reason.EXECUTE_READ);var frame=e.begin(new PcodeProgram(language,Arrays.asList(code),lib.getSymbols(language)){});int steps=0;while(!frame.isFinished()&&steps++<100000)e.step(frame,lib);equal(true,frame.isFinished(),"bounded execution");}
    PcodeOp[] raw(long entry,int terminal)throws Exception{var context=new ProcessorContextImpl(currentProgram.getLanguage());for(String field:List.of("c_is16","c_flow_delay","c_schedule_entry"))context.setRegisterValue(new RegisterValue(currentProgram.getRegister(field),BigInteger.ZERO));context.setRegisterValue(new RegisterValue(currentProgram.getRegister("c_branch_terminal"),BigInteger.valueOf(terminal)));var address=toAddr(entry);var memory=new DumbMemBufferImpl(currentProgram.getMemory(),address);var proto=currentProgram.getLanguage().parse(memory,context,false);return new PseudoInstruction(currentProgram,address,proto,memory,context).getPcode(false);}
    @Override protected void run()throws Exception{
        C6000PacketContext.prime(currentProgram,monitor);arithmetic=BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());var rows=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonArray();int count=0,refused=0;
        for(var item:rows){var row=item.getAsJsonObject();long entry=row.get("entry").getAsLong();var at=toAddr(entry);var scope=new AddressSet(at,at.add(127));new DisassembleCommand(at,scope,false).applyTo(currentProgram,monitor);var f=currentProgram.getFunctionManager().createFunction(row.get("name").getAsString(),at,scope,SourceType.USER_DEFINED);
            var discovery=raw(entry,0);equal(true,Arrays.stream(discovery).anyMatch(op->op.getOpcode()==PcodeOp.CBRANCH),"discovery retains conditional fallthrough");equal(true,Arrays.stream(discovery).anyMatch(op->op.getOpcode()==PcodeOp.BRANCHIND),"discovery retains existing indirect semantics");var terminal=raw(entry,1);equal(false,Arrays.stream(terminal).anyMatch(op->op.getOpcode()==PcodeOp.CALLOTHER),"terminal semantics are transparent");equal(true,Arrays.stream(terminal).anyMatch(op->op.getOpcode()==PcodeOp.BRANCHIND),"terminal indirect transfer");
            if(row.has("refused")){boolean rejected=false;try{new C6000PipelineCompiler(currentProgram,f).compileStoreTail(new C6000PipelineCompiler.StoreTailContract(2,"Synthetic idle observation"));}catch(IllegalArgumentException error){if(!error.getMessage().contains(row.get("refused").getAsString()))throw error;rejected=true;}equal(true,rejected,"unresolved target refused");refused++;continue;}
            var nativeState=initial(row);execute(terminal,nativeState);equal(row.get("taken").getAsBoolean()?0x9000L:entry+4,value(nativeState,"PC"),"native predicate truth table");
            boolean strict=false;try{new C6000PipelineCompiler(currentProgram,f).compile();}catch(IllegalArgumentException error){if(!error.getMessage().contains("return leaves architectural pipeline effects pending"))throw error;strict=true;}equal(true,strict,"ordinary store-tail refusal retained");
            var result=new C6000PipelineCompiler(currentProgram,f).compileStoreTail(new C6000PipelineCompiler.StoreTailContract(2,"Synthetic drained entry; no caller issue, interrupt or observation during two idle advances"));var state=initial(row);execute(result.schedule().code(),state);
            for(var expected:row.getAsJsonObject("expected").entrySet())equal(expected.getValue().getAsLong(),value(state,expected.getKey()),row.get("name")+" "+expected.getKey());
            byte[] memory=state.getVar(toAddr(0x8000),16,false,PcodeExecutorStatePiece.Reason.INSPECT),wanted=new byte[16];Arrays.fill(wanted,(byte)0x5a);byte[] word=arithmetic.fromConst(0x12345678,4);System.arraycopy(word,0,wanted,0,4);wanted[4]=(byte)0x9a;equal(true,Arrays.equals(wanted,memory),"delay stores survive either branch outcome; guards intact");count++;
        }
        equal(108,count,"complete predicate matrix");equal(2,refused,"unresolved targets");println("C6000_PIPELINE_PREDICATED_RETURN_OK cases="+count+" refused="+refused);
    }
}
