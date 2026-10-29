// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Exercise the installed injection library and native decompiler, without a payload override.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.pcode.exec.*;
import ghidra.util.task.*;
import c6000.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
public class C6000PipelineCallContractTest extends GhidraScript {
 final Gson json=new GsonBuilder().setPrettyPrinting().create();int refusals;
 interface Action{void run()throws Exception;}
 long n(JsonObject row,String key){return row.get(key).getAsLong();}
 void same(Object wanted,Object actual,String why){if(!Objects.equals(wanted,actual))throw new AssertionError(why+" wanted="+wanted+" actual="+actual);}
 void refuses(Action action,String reason)throws Exception{try{action.run();}catch(Exception error){if(!error.toString().contains(reason))throw new AssertionError("Wrong refusal "+error,error);refusals++;return;}throw new AssertionError("Accepted "+reason);}
 String hash(long first,long end)throws Exception{long start=first&~31L;byte[] bytes=new byte[(int)(((end+31)&~31L)-start)];currentProgram.getMemory().getBytes(toAddr(start),bytes);return C6000PipelineContracts.sha256(bytes);}
 C6000PipelineCompiler.TraceWindow window(long owner,long end)throws Exception{return new C6000PipelineCompiler.TraceWindow(owner,owner,end,hash(owner,end));}
 Function define(long start,long end,String name)throws Exception{var range=new AddressSet(toAddr(start),toAddr(end-1));new DisassembleCommand(toAddr(start),range,false).applyTo(currentProgram,monitor);return currentProgram.getFunctionManager().createFunction(name,toAddr(start),range,SourceType.USER_DEFINED);}
 PcodeOp[] inject(Function f)throws Exception{var context=new InjectContext();context.baseAddr=f.getEntryPoint();var payload=currentProgram.getCompilerSpec().getPcodeInjectLibrary().getPayload(InjectPayload.CALLOTHERFIXUP_TYPE,"c6000_pipeline");if(!(payload instanceof C6000PipelinePayload))throw new AssertionError("Non-production payload "+payload);return payload.getPcode(currentProgram,context);}
 void stale(Function f,Action mutation,Action restore,String reason)throws Exception{try{mutation.run();refuses(()->inject(f),reason);}finally{restore.run();}inject(f);}
 String decompile(Function f)throws Exception{var d=new DecompInterface();try{d.setOptions(new DecompileOptions());if(!d.openProgram(currentProgram))throw new AssertionError(d.getLastMessage());var result=d.decompileFunction(f,30,monitor);if(!result.decompileCompleted())throw new AssertionError(result.getErrorMessage());return result.getDecompiledFunction().getC();}finally{d.dispose();}}
 String options(){var options=currentProgram.getOptions(C6000PipelineSchedules.OPTIONS);var text=new TreeMap<String,String>();for(String key:options.getOptionNames())text.put(key,Objects.toString(options.getObject(key,null)));return text.toString();}
 void patch(long pc,int word)throws Exception{var at=toAddr(pc);var old=getInstructionAt(at);var refs=old==null?new Reference[0]:old.getReferencesFrom();var flow=old==null?FlowOverride.NONE:old.getFlowOverride();currentProgram.getListing().clearCodeUnits(at,at.add(3),false);currentProgram.getMemory().setInt(at,word);new DisassembleCommand(at,new AddressSet(at,at.add(3)),false).applyTo(currentProgram,monitor);var instruction=getInstructionAt(at);if(instruction!=null)instruction.setFlowOverride(flow);for(var ref:refs)currentProgram.getReferenceManager().addReference(ref);}
 void selector(long pc,boolean enabled)throws Exception{var at=toAddr(pc);var old=getInstructionAt(at);int length=old.getLength();var refs=old.getReferencesFrom();var flow=old.getFlowOverride();currentProgram.getListing().clearCodeUnits(at,at.add(length-1),false);currentProgram.getProgramContext().setValue(currentProgram.getRegister("c_schedule_entry"),at,at,enabled?BigInteger.ONE:BigInteger.ZERO);new DisassembleCommand(at,new AddressSet(at,at.add(length-1)),false).applyTo(currentProgram,monitor);getInstructionAt(at).setFlowOverride(flow);for(var ref:refs)currentProgram.getReferenceManager().addReference(ref);}
 void execute(Function f,PcodeOp[] payload,long expected)throws Exception{
  var lang=(ghidra.app.plugin.processors.sleigh.SleighLanguage)currentProgram.getLanguage();var a=BytesPcodeArithmetic.forLanguage(lang);var state=new BytesPcodeExecutorState(lang,PcodeStateCallbacks.NONE);
  for(var r:lang.getRegisters())if(!r.isProcessorContext()&&r.getMinimumByteSize()==4)state.setVar(r,a.fromConst(0,4));
  for(var x:Map.of("B3",0x9000L,"B15",0x8100L,"A4",0x8200L,"A6",expected,"B7",0x55L).entrySet())state.setVar(currentProgram.getRegister(x.getKey()),a.fromConst(x.getValue(),4));state.setVar(toAddr(0x8000),0x400,false,new byte[0x400]);
  // The standard entry wrapper returns C6000_PIPE_RET after the payload falls through.
  var code=Arrays.copyOf(payload,payload.length+1);code[payload.length]=new PcodeOp(f.getEntryPoint(),payload.length,PcodeOp.RETURN,new Varnode[]{new Varnode(currentProgram.getRegister("C6000_PIPE_RET").getAddress(),4)},null);
  var library=PcodeUseropLibrary.<byte[]>nil();var executor=new PcodeExecutor<byte[]>(lang,a,state,PcodeExecutorStatePiece.Reason.EXECUTE_READ);var frame=executor.begin(new PcodeProgram(lang,Arrays.asList(code),library.getSymbols(lang)){});int steps=0;while(!frame.isFinished()&&steps++<100000)executor.step(frame,library);if(!frame.isFinished())throw new AssertionError("Injection did not finish");
  same(0x9000L,a.toLong(state.getVar(currentProgram.getRegister("PC"),PcodeExecutorStatePiece.Reason.INSPECT),PcodeArithmetic.Purpose.INSPECT),"normal injected return PC");same(expected,a.toLong(state.getVar(toAddr(0x8200),4,false,PcodeExecutorStatePiece.Reason.INSPECT),PcodeArithmetic.Purpose.INSPECT),"normal injected store");
 }
 protected void run()throws Exception{
  C6000PacketContext.prime(currentProgram,monitor);var rows=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonArray();var result=new JsonArray();var directory=Path.of(getScriptArgs()[1]).getParent();int checked=0;
  for(var e:rows){var row=e.getAsJsonObject();String name=row.get("name").getAsString();long c=n(row,"caller"),end=n(row,"caller_end");var f=define(c,end,name);f.updateFunction("__c6000",new ReturnParameterImpl(VoidDataType.dataType,currentProgram),List.of(new ParameterImpl("dest",new PointerDataType(UnsignedIntegerDataType.dataType),currentProgram),new ParameterImpl("unused",UnsignedIntegerDataType.dataType,currentProgram),new ParameterImpl("value",UnsignedIntegerDataType.dataType,currentProgram)),Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED);
   Set<String> writes=row.has("entry_writes")?new HashSet<>(Arrays.asList(json.fromJson(row.get("entry_writes"),String[].class))):Set.of();var helpers=new LinkedHashMap<Long,Function>();var plans=new ArrayList<C6000PipelineCompiler.ClosedCallPlan>();var refs=currentProgram.getReferenceManager();
   for(var x:row.getAsJsonArray("sites")){var site=x.getAsJsonObject();long target=n(site,"callee");if(!helpers.containsKey(target))helpers.put(target,define(target,n(site,"callee_end"),name+"_helper_"+Long.toHexString(target)));
    plans.add(new C6000PipelineCompiler.ClosedCallPlan(currentProgram.getLanguageID().getIdAsString(),window(c,end),window(target,n(site,"callee_end")),c,null,n(site,"call"),n(site,"link"),n(site,"continuation"),n(site,"callee_return"),n(row,"caller_return"),new C6000PipelineCompiler.TraceEntry(true,writes),"Synthetic isolated drained entry; original owner windows and live caller delay packets"));
    refs.addMemoryReference(toAddr(n(site,"call")),toAddr(target),RefType.COMPUTED_CALL,SourceType.USER_DEFINED,0);
   }
   var external=toAddr(c+0x600);for(long target:helpers.keySet()){refs.addMemoryReference(external,toAddr(target),RefType.UNCONDITIONAL_CALL,SourceType.USER_DEFINED,0);currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(target));setEOLComment(toAddr(target),"retain helper annotation");}
   setEOLComment(toAddr(c),"retain caller annotation");refs.addMemoryReference(toAddr(c),toAddr(0x8000),RefType.DATA,SourceType.USER_DEFINED,0);
   var bodies=new LinkedHashMap<Long,String>();bodies.put(c,f.getBody().toString());for(var h:helpers.values())bodies.put(h.getEntryPoint().getOffset(),h.getBody().toString());String bytes=hash(c,c+0x400),initialOptions=options();
   if(checked==0){
    var p=plans.get(0);var bounded=new C6000PipelineCompiler.ClosedCallPlan(p.languageId(),p.caller(),p.callee(),p.startPc(),p.caller().end(),p.callPc(),p.linkPc(),p.continuation(),p.calleeReturnPc(),null,p.entry(),p.evidence());refuses(()->C6000PipelineSchedules.enableClosedCalls(currentProgram,f,List.of(bounded),monitor),"complete caller return");
    var cancel=new TaskMonitorAdapter(true);cancel.cancel();refuses(()->C6000PipelineSchedules.enableClosedCalls(currentProgram,f,plans,cancel),"CancelledException");
    long target=helpers.keySet().iterator().next();refs.addMemoryReference(external,toAddr(target+4),RefType.UNCONDITIONAL_JUMP,SourceType.USER_DEFINED,1);
    refuses(()->C6000PipelineSchedules.enableClosedCalls(currentProgram,f,plans,monitor),"alternate entry");refs.delete(refs.getReference(external,toAddr(target+4),1));
    same(initialOptions,options(),"failed activation leaves options unchanged");same(false,C6000PipelineContracts.isRecorded(currentProgram,f),"failed activation never binds");same(false,BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_schedule_entry"),toAddr(c),false)),"failed activation never enables");
   }
   var trace=C6000PipelineSchedules.enableClosedCalls(currentProgram,f,plans,monitor);same(plans,C6000PipelineSchedules.closedCalls(currentProgram,f),"stored contracts round trip");
   same(bytes,hash(c,c+0x400),"activation keeps code bytes");for(var h:bodies.entrySet())same(h.getValue(),currentProgram.getFunctionManager().getFunctionAt(toAddr(h.getKey())).getBody().toString(),"activation keeps owner bodies");
   for(var h:helpers.values()){same(false,C6000PipelineContracts.isRecorded(currentProgram,h),"callee not independently enabled");same("retain helper annotation",getEOLComment(h.getEntryPoint()),"helper annotation");}
   same("retain caller annotation",getEOLComment(toAddr(c)),"caller annotation");if(refs.getReference(toAddr(c),toAddr(0x8000),0)==null)throw new AssertionError("Lost entry reference");
   var ops=inject(f);same(trace.schedule().code().length,ops.length,"standard payload contains full trace");for(int k=0;k<ops.length-1;k++)same(trace.schedule().code()[k].toString(),ops[k].toString(),"standard payload op "+k);execute(f,ops,n(row,"memory_word"));
   long modifications=currentProgram.getModificationNumber();String configured=options();C6000PipelineSchedules.enableClosedCalls(currentProgram,f,plans,monitor);same(configured,options(),"idempotent options");same(modifications,currentProgram.getModificationNumber(),"idempotent activation is read-only");new C6000PipelineScheduleAnalyzer().added(currentProgram,currentProgram.getMemory(),monitor,new MessageLog());same(modifications,currentProgram.getModificationNumber(),"unchanged analyzer is read-only");
   String code=decompile(f);if(code.contains("c6000_pipeline(")||!code.contains("dest")||!code.contains("value")||!code.contains("="))throw new AssertionError("Opaque or lost store: "+code);for(var h:helpers.values())if(code.contains(h.getName()+"("))throw new AssertionError("Sequential call decompilation: "+code);Files.writeString(directory.resolve(name+".c"),code);
   if(checked==0){
    var option=currentProgram.getOptions(C6000PipelineSchedules.OPTIONS);String key=C6000PipelineSchedules.closedCallsKey(f),stored=option.getString(key,"");
    stale(f,()->option.setString(key,stored+" "),()->option.setString(key,stored),"stale");stale(f,()->option.setString(key,"{bad"),()->option.setString(key,stored),"Invalid closed-call");stale(f,()->option.removeOption(key),()->option.setString(key,stored),"another function");
    String hazard=option.getString(C6000PipelineSchedules.hazardsKey(f),"");stale(f,()->option.setString(C6000PipelineSchedules.hazardsKey(f),"A4"),()->option.setString(C6000PipelineSchedules.hazardsKey(f),hazard),"hazard assumptions changed");
    long target=helpers.keySet().iterator().next();int original=currentProgram.getMemory().getInt(toAddr(target));stale(f,()->patch(target,original^0x80),()->patch(target,original),"byte hash mismatch");
    var helper=helpers.get(target);var body=new AddressSet(helper.getBody());stale(f,()->helper.setBody(new AddressSet(toAddr(target),toAddr(target+3))),()->helper.setBody(body),"ownership");
    stale(f,()->refs.addMemoryReference(external,toAddr(target+4),RefType.UNCONDITIONAL_JUMP,SourceType.USER_DEFINED,1),()->refs.delete(refs.getReference(external,toAddr(target+4),1)),"alternate entry");
    stale(f,()->currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(target+4)),()->currentProgram.getSymbolTable().removeExternalEntryPoint(toAddr(target+4)),"alternate entry");
    stale(f,()->selector(target,true),()->selector(target,false),"another schedule entry");
    stale(f,()->selector(c,false),()->selector(c,true),"entry selector changed");
    var source=new C6000PipelineContracts.SourceWindow(c&~31L,32,hash(c&~31L,(c&~31L)+32));var review=C6000PipelineContracts.review(currentProgram,f,plans.get(0).evidence(),writes,List.of(source),monitor);C6000PipelineContracts.record(currentProgram,f,review,monitor);refuses(()->inject(f),"not been activated");new C6000PipelineScheduleAnalyzer().added(currentProgram,currentProgram.getMemory(),monitor,new MessageLog());inject(f);
   }
   row.addProperty("normal_decompiler",true);row.addProperty("states",trace.schedule().states());result.add(row);checked++;println("CALL_CONTRACT_CASE "+name);
  }Files.writeString(Path.of(getScriptArgs()[1]),json.toJson(result));println("C6000_PIPELINE_CALL_CONTRACT_OK cases="+checked+" refusals="+refusals+" native_decompiler=true");
 }
}
