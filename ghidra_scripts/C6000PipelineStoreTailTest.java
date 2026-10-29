// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B 3.5, 3.9.2, 4.2.3/4.2.6: captured E1 stores mature in E3.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.pcode.exec.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import c6000.*;

public class C6000PipelineStoreTailTest extends GhidraScript {
    BytesPcodeArithmetic arithmetic;
    int checks=0;
    interface Action { void run() throws Exception; }
    void equal(Object expected,Object actual,String why){checks++;if(!Objects.equals(expected,actual))throw new AssertionError(why+" expected="+expected+" actual="+actual);}
    void refuses(Action action,String reason)throws Exception{try{action.run();}catch(Exception error){if(!error.toString().contains(reason))throw new AssertionError("Wrong refusal "+error,error);checks++;return;}throw new AssertionError("Accepted "+reason);}
    long read(BytesPcodeExecutorState state,Varnode v){return arithmetic.toLong(state.getVar(v,PcodeExecutorStatePiece.Reason.INSPECT),PcodeArithmetic.Purpose.INSPECT);}
    long reg(BytesPcodeExecutorState state,String name){return read(state,new Varnode(currentProgram.getRegister(name).getAddress(),4));}
    byte[] ram(BytesPcodeExecutorState state){return state.getVar(toAddr(0x8000),256,false,PcodeExecutorStatePiece.Reason.INSPECT);}
    PcodeOp[] injected(Function f)throws Exception{var context=new InjectContext();context.baseAddr=f.getEntryPoint();return new C6000PipelinePayload("store-tail-regression").getPcode(currentProgram,context);}
    C6000PipelineCompiler.StoreTailContract contract(int count){return new C6000PipelineCompiler.StoreTailContract(count,"Synthetic observation: no caller issue, interrupt or memory observation until contracted idle advances complete");}
    void execute(Function f,JsonObject row,int idle)throws Exception{
        String body=f.getBody().toString();var result=new C6000PipelineCompiler(currentProgram,f).compileStoreTail(contract(idle));equal(body,f.getBody().toString(),"compilation preserves ownership");
        var state=new BytesPcodeExecutorState(currentProgram.getLanguage(),PcodeStateCallbacks.NONE);
        for(var r:currentProgram.getLanguage().getRegisters())if(!r.isProcessorContext()&&r.getMinimumByteSize()==4)state.setVar(r,arithmetic.fromConst(0,4));
        for(var input:row.getAsJsonObject("input").entrySet())state.setVar(currentProgram.getRegister(input.getKey()),arithmetic.fromConst(input.getValue().getAsLong(),4));
        byte[] initial=new byte[256];Arrays.fill(initial,(byte)0x5a);state.setVar(toAddr(0x8000),256,false,initial);
        var language=(SleighLanguage)currentProgram.getLanguage();var library=PcodeUseropLibrary.<byte[]>nil();
        var executor=new PcodeExecutor<byte[]>(language,arithmetic,state,PcodeExecutorStatePiece.Reason.EXECUTE_READ);
        var frame=executor.begin(new PcodeProgram(language,Arrays.asList(result.schedule().code()),library.getSymbols(language)){});
        var boundaries=new HashMap<Integer,C6000PipelineCompiler.StoreTailBoundary>();for(var boundary:result.boundaries())boundaries.put(boundary.pcodeIndex(),boundary);
        int steps=0,seen=0,idleCycles=0;byte[] predicted=initial.clone();
        while(!frame.isFinished()&&steps++<100000){int index=frame.index();var boundary=boundaries.get(index);
            if(boundary!=null){seen++;equal(true,Arrays.equals(initial,ram(state)),"no early store");int count=row.has("ages")?row.getAsJsonArray("ages").size():1;equal(count,boundary.stores().size(),"pending instruction count");
                for(int k=0;k<count;k++){var store=boundary.stores().get(k);int age=row.has("ages")?row.getAsJsonArray("ages").get(k).getAsInt():row.get("age").getAsInt();equal(age,store.age(),"pending age");equal(3-age,store.remainingAdvances(),"exact remaining advances");equal(row.get("enabled").getAsBoolean()?1L:0L,read(state,store.predicate()),"sampled predicate");
                 for(var write:store.writes())if(read(state,write.enabled())!=0){int address=(int)read(state,write.address())-0x8000;var bytes=state.getVar(write.value(),PcodeExecutorStatePiece.Reason.INSPECT);if(address<0||address+bytes.length>predicted.length)throw new AssertionError("captured address outside arena");System.arraycopy(bytes,0,predicted,address,bytes.length);}
                }
                equal(row.get("memory").getAsString(),HexFormat.of().formatHex(predicted),"captured memory effects match independent byte oracle");
            }
            var pc=result.schedule().cycleStarts().get(index);if(pc!=null&&pc==C6000PipelineCompiler.POST_RETURN_IDLE_PC){idleCycles++;if(idleCycles==2&&row.has("middle_memory"))equal(row.get("middle_memory").getAsString(),HexFormat.of().formatHex(ram(state)),"first store committed, second pending");if(idleCycles<3-row.get("age").getAsInt())equal(true,Arrays.equals(initial,ram(state)),"store has not reached E3");}
            executor.step(frame,library);
        }
        equal(true,frame.isFinished(),"bounded completion");equal(1,seen,"one return landing");equal(idle,idleCycles,"exact contracted idle count");equal(row.get("memory").getAsString(),HexFormat.of().formatHex(ram(state)),"final bytes and guards");
        for(var expected:row.getAsJsonObject("expected").entrySet())equal(expected.getValue().getAsLong(),reg(state,expected.getKey()),expected.getKey());
    }
    @Override protected void run()throws Exception{
        C6000PacketContext.prime(currentProgram,monitor);arithmetic=BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());
        var rows=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonArray();var records=new JsonArray();int executed=0,rejected=0;Function activation=null;
        for(var item:rows){var row=item.getAsJsonObject();var at=toAddr(row.get("entry").getAsLong());var scope=new AddressSet(at,at.add(127));new DisassembleCommand(at,scope,false).applyTo(currentProgram,monitor);var f=currentProgram.getFunctionManager().createFunction(row.get("name").getAsString(),at,scope,SourceType.USER_DEFINED);
            if(row.has("error")){refuses(()->C6000PipelineSchedules.enableStoreTail(currentProgram,f,"Synthetic drained entry",Set.of(),contract(row.get("advances").getAsInt()),monitor),row.get("error").getAsString());equal(false,currentProgram.getOptions(C6000PipelineSchedules.OPTIONS).contains(C6000PipelineSchedules.storeTailKey(f)),"refusal does not record tail contract");rejected++;}
            else{
                if(row.has("ages")&&row.getAsJsonArray("ages").isEmpty())new C6000PipelineCompiler(currentProgram,f).compile();else refuses(()->new C6000PipelineCompiler(currentProgram,f).compile(),"return leaves architectural pipeline effects pending");execute(f,row,2);executed++;
                if(row.get("age").getAsInt()==2){execute(f,row,1);executed++;}else refuses(()->new C6000PipelineCompiler(currentProgram,f).compileStoreTail(contract(1)),"idle budget is too short");
                if(activation==null)activation=f;
            }
            records.add(row);
        }
        refuses(()->new C6000PipelineCompiler.StoreTailContract(0,"Evidence"),"one or two idle");refuses(()->new C6000PipelineCompiler.StoreTailContract(3,"Evidence"),"one or two idle");refuses(()->new C6000PipelineCompiler.StoreTailContract(2," "),"explicit observation evidence");
        final Function f=activation;var enabled=C6000PipelineSchedules.enableStoreTail(currentProgram,f,"Synthetic drained entry",Set.of(),contract(2),monitor);injected(f);equal(enabled.states(),C6000PipelineSchedules.enableStoreTail(currentProgram,f,"Synthetic drained entry",Set.of(),contract(2),monitor).states(),"idempotent activation");C6000PipelineContracts.activate(currentProgram,f,monitor);
        var decompiler=new DecompInterface();try{decompiler.setOptions(new DecompileOptions());equal(true,decompiler.openProgram(currentProgram),"open decompiler");var d=decompiler.decompileFunction(f,30,monitor);equal(true,d.decompileCompleted(),"decompile contracted stores");var code=d.getDecompiledFunction().getC();equal(false,code.contains("c6000_pipeline"),"injection expanded");equal(false,code.contains("Bad instruction"),"no failed injection");}finally{decompiler.dispose();}
        var options=currentProgram.getOptions(C6000PipelineSchedules.OPTIONS);String key=C6000PipelineSchedules.storeTailKey(f),saved=options.getString(key,"");
        options.setString(key,"{\"idleAdvances\":2,\"evidence\":\"different observation assumptions\"}");refuses(()->injected(f),"stale");options.setString(key,saved);injected(f);
        options.removeOption(key);refuses(()->injected(f),"return leaves architectural pipeline effects pending");options.setString(key,saved);injected(f);
        options.setString(key,"{}");refuses(()->injected(f),"Invalid post-return");options.setString(key,saved);injected(f);
        refuses(()->C6000PipelineSchedules.enableStoreTail(currentProgram,f,"Synthetic drained entry",Set.of(),contract(1),monitor),"different store-tail contract");equal(saved,options.getString(key,""),"refused replacement preserves binding");
        var patch=f.getEntryPoint().add(64);byte[] old=new byte[4];currentProgram.getMemory().getBytes(patch,old);currentProgram.getListing().clearCodeUnits(patch,patch.add(3),false);currentProgram.getMemory().setInt(patch,0x1234);new DisassembleCommand(patch,new AddressSet(patch,patch.add(3)),false).applyTo(currentProgram,monitor);refuses(()->injected(f),"stale");currentProgram.getListing().clearCodeUnits(patch,patch.add(3),false);currentProgram.getMemory().setBytes(patch,old);new DisassembleCommand(patch,new AddressSet(patch,patch.add(3)),false).applyTo(currentProgram,monitor);injected(f);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().create().toJson(records));
        equal(4,rejected,"refusal matrix");if(executed<200)throw new AssertionError("Incomplete store-tail matrix");println("C6000_PIPELINE_STORE_TAIL_OK cases="+rows.size()+" executions="+executed+" refused="+rejected+" checks="+checks);
    }
}
