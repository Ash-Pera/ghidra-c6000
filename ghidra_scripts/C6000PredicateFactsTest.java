// SPDX-License-Identifier: Apache-2.0
// @category C6000
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.pcode.exec.*;
import java.util.*;
import java.nio.file.*;
public class C6000PredicateFactsTest extends GhidraScript {
 static class Case {String name;long at;boolean accepted;}
 protected void run()throws Exception{
  c6000.C6000PacketContext.prime(currentProgram,monitor);var cases=new com.google.gson.Gson().fromJson(Files.readString(Paths.get(getScriptArgs()[0])),Case[].class);int accepted=0,refused=0,executed=0;
  var arithmetic=BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());var reason=PcodeExecutorStatePiece.Reason.INSPECT;
  for(var item:cases){var function=currentProgram.getFunctionManager().createFunction(item.name,toAddr(item.at),new AddressSet(toAddr(item.at),toAddr(item.at+511)),SourceType.USER_DEFINED);c6000.C6000PipelineCompiler.Result result;
   try{result=new c6000.C6000PipelineCompiler(currentProgram,function).compile();if(!item.accepted)throw new AssertionError("Unsoundly accepted "+item.name);accepted++;}
   catch(IllegalArgumentException error){if(item.accepted||!error.getMessage().contains("return leaves architectural pipeline effects pending"))throw new AssertionError(item.name+" unexpected refusal "+error);println("EXPECTED_REFUSAL "+item.name);refused++;continue;}
   println("SUPPORTED "+item.name+" states="+result.states());
   for(long initial:new long[]{0,1,0xffffffffL}){
    var state=new BytesPcodeExecutorState(currentProgram.getLanguage(),PcodeStateCallbacks.NONE);
    for(var register:currentProgram.getLanguage().getRegisters())if(!register.isProcessorContext()&&register.getMinimumByteSize()==4)state.setVar(register,arithmetic.fromConst(0,4));
    for(var entry:Map.of("B0",initial,"A4",0x8000L,"B4",0x8000L,"B3",0x9000L).entrySet())state.setVar(currentProgram.getRegister(entry.getKey()),arithmetic.fromConst(entry.getValue(),4));
    state.setVar(toAddr(0x8000),128,false,new byte[128]);state.setVar(toAddr(0x8000),4,false,arithmetic.fromConst(1,4));
    var executor=new PcodeExecutor<byte[]>((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage()), state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);var library=PcodeUseropLibrary.<byte[]>nil();var frame=executor.begin(new ghidra.pcode.exec.PcodeProgram((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), Arrays.asList(result.code()),library.getSymbols((ghidra.app.plugin.processors.sleigh.SleighLanguage)currentProgram.getLanguage())) {});int steps=0;
    while(!frame.isFinished()&&steps++<100000)executor.step(frame,library);if(!frame.isFinished())throw new AssertionError(item.name+" exceeded step bound");
    long pc=arithmetic.toLong(state.getVar(currentProgram.getRegister("PC"),reason),PcodeArithmetic.Purpose.INSPECT);if(pc!=0x9000)throw new AssertionError(item.name+" wrong captured return");
    if(arithmetic.toLong(state.getVar(toAddr(0x8000),4,false,reason),PcodeArithmetic.Purpose.INSPECT)!=1)throw new AssertionError("Unexpected memory write");executed++;
   }
  }
  println("PREDICATE_FACTS_TEST_OK accepted="+accepted+" refused="+refused+" executions="+executed);
 }
}
