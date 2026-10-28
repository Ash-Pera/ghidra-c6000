// SPDX-License-Identifier: Apache-2.0
package c6000;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
/** Shared physical-packet proof for ordinary analysis and reviewed recovery.
 * No clearing, flow following, context writes, header creation or body expansion.
 * SPRUFE8B sections 3.5 and 3.10.2/3.10.4.
 */
public final class C6000ParallelPeers {
 static final Gson JSON=new GsonBuilder().setPrettyPrinting().create();
 public record Candidate(long address,int width,String bytes,String listing,String pcodeSha,String contextSha,Long owner) {}
 public record Parsed(Instruction instruction,InstructionPrototype prototype,ProcessorContextImpl context,String pcodeSha,String contextSha) {}
 public record Prepared(Candidate row,Parsed parsed) {}
 private final Program currentProgram;
 private final TaskMonitor monitor;
 private final long sourceStart,sourceEnd;
 private Address toAddr(long pc){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(pc);}
 public C6000ParallelPeers(Program program,TaskMonitor task,long start,long end)throws Exception{
  currentProgram=program;monitor=task;sourceStart=start;sourceEnd=end;

 }
 public Collection<Prepared> candidates(){return List.copyOf(prepared.values());}
 public List<Object> reports(){return List.copyOf(anchors);}
 public void inspect(long anchor,long limit)throws Exception{
  var row=new JsonObject();row.addProperty("address",anchor);row.addProperty("allowed_end",limit);
  var original=currentProgram.getListing().getInstructionAt(toAddr(anchor));
  if(original==null)throw new IllegalArgumentException("missing anchor");
  row.addProperty("expected_bytes",HexFormat.of().formatHex(bytes(anchor,original.getLength())));inspect(row);
 }

 private final TreeMap<Long,Prepared> prepared=new TreeMap<>();
 private final List<Object> anchors=new ArrayList<>();
 public String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
 public String hash(String text)throws Exception{return hash(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));}
 public byte[] bytes(long pc,int size)throws Exception{if(pc<sourceStart||size<0||pc+size>sourceEnd)throw new IllegalArgumentException("outside pinned source bounds");byte[] bytes=new byte[size];if(currentProgram.getMemory().getBytes(toAddr(pc),bytes)!=size)throw new IllegalArgumentException("short source read");return bytes;}
 void field(ProcessorContextImpl context,String name,int value){context.setRegisterValue(new RegisterValue(currentProgram.getRegister(name),BigInteger.valueOf(value)));}
 int width(long pc)throws Exception{return C6000ExecutionPackets.instructionLengthAt(currentProgram,toAddr(pc));}
 long next(long pc,int width)throws Exception{long result=pc+width;if((result&31)==28){int value=currentProgram.getMemory().getInt(toAddr(result));if((value>>>28)==14){bytes(result,4);result+=4;}}return result;}
 ProcessorContextImpl stored(long pc){var context=new ProcessorContextImpl(currentProgram.getLanguage());var value=currentProgram.getProgramContext().getRegisterValue(currentProgram.getLanguage().getContextBaseRegister(),toAddr(pc));if(value!=null)context.setRegisterValue(value);return context;}
 public String pcode(Instruction instruction)throws Exception{var text=new StringBuilder();var code=instruction.getPcode();if(code.length==0&&!instruction.getMnemonicString().equals("NOP"))throw new IllegalArgumentException("empty/opaque p-code");int operationIndex=0;for(var op:code){int kind=op.getOpcode();if(Set.of(PcodeOp.UNIMPLEMENTED,PcodeOp.CALLOTHER,PcodeOp.CALL,PcodeOp.CALLIND,PcodeOp.RETURN,PcodeOp.BRANCHIND).contains(kind))throw new IllegalArgumentException("opaque/control p-code");if((kind==PcodeOp.BRANCH||kind==PcodeOp.CBRANCH)&&!op.getInput(0).isConstant())throw new IllegalArgumentException("external p-code branch");if(kind==PcodeOp.BRANCH||kind==PcodeOp.CBRANCH){long destination=operationIndex+(long)(int)op.getInput(0).getOffset();if(destination<0||destination>code.length)throw new IllegalArgumentException("invalid internal p-code branch");}operationIndex++;text.append(kind).append(':');var nodes=new ArrayList<Varnode>();nodes.add(op.getOutput());nodes.addAll(Arrays.asList(op.getInputs()));for(var node:nodes){if(node==null)text.append("null");else text.append(node.getAddress().getAddressSpace().getName()).append('@').append(Long.toUnsignedString(node.getOffset(),16)).append('/').append(node.getSize());text.append(';');}text.append('\n');}return hash(text.toString());}
 public Parsed parse(long pc,boolean physical,boolean peer)throws Exception{
  int width=width(pc);bytes(pc,width);var context=stored(pc);
  if(physical)for(var item:C6000PacketContext.physicalDecodeFields(currentProgram,toAddr(pc)).entrySet())field(context,item.getKey(),item.getValue());
  var memory=new DumbMemBufferImpl(currentProgram.getMemory(),toAddr(pc));var prototype=currentProgram.getLanguage().parse(memory,context,false);var instruction=new PseudoInstruction(currentProgram,toAddr(pc),prototype,memory,context);
  if(instruction.getLength()!=width)throw new IllegalArgumentException("stored/physical width mismatch");
  if(peer&&(instruction.getFlowType().isJump()||instruction.getFlowType().isCall()||instruction.getFlowType().isTerminal()))throw new IllegalArgumentException("control-flow peer requires separate review");
  String code=peer?pcode(instruction):"anchor";var base=currentProgram.getLanguage().getContextBaseRegister();var value=context.getRegisterValue(base);
  return new Parsed(instruction,prototype,context,code,hash(String.valueOf(value)));
 }
 public Long owner(long pc){var function=currentProgram.getFunctionManager().getFunctionContaining(toAddr(pc));return function==null?null:function.getEntryPoint().getOffset();}
 public void undefined(long pc,int size,Long sourceOwner)throws Exception{
  Long first=owner(pc);if(first!=null&&!first.equals(sourceOwner))throw new IllegalArgumentException("foreign owner");if(currentProgram.getFunctionManager().getFunctionAt(toAddr(pc))!=null)throw new IllegalArgumentException("function entry conflict");
  for(int k=0;k<size;k++){var at=toAddr(pc+k);if(currentProgram.getListing().getInstructionContaining(at)!=null||currentProgram.getListing().getDefinedDataContaining(at)!=null)throw new IllegalArgumentException("existing code/data overlap");if(!Objects.equals(first,owner(pc+k)))throw new IllegalArgumentException("partial owner extent");}
 }
 public void inspect(JsonObject anchor)throws Exception{
  long start=anchor.get("address").getAsLong(),limit=anchor.get("allowed_end").getAsLong();var output=new LinkedHashMap<String,Object>();output.put("address",start);output.put("allowed_end",limit);var peers=new ArrayList<Object>();output.put("peers",peers);
  try{
   if(start<sourceStart||limit>sourceEnd||limit<=start||limit-start>64)throw new IllegalArgumentException("invalid anchor bound");var original=currentProgram.getListing().getInstructionAt(toAddr(start));if(original==null)throw new IllegalArgumentException("anchor is not a defined instruction");int firstWidth=width(start);if(original.getLength()!=firstWidth)throw new IllegalArgumentException("anchor physical extent differs");if(!HexFormat.of().formatHex(bytes(start,firstWidth)).equals(anchor.get("expected_bytes").getAsString()))throw new IllegalArgumentException("anchor bytes changed");var first=parse(start,true,false);Long sourceOwner=owner(start);for(int k=0;k<firstWidth;k++)if(!Objects.equals(sourceOwner,owner(start+k)))throw new IllegalArgumentException("anchor partial owner extent");output.put("anchor_listing",original.toString());output.put("anchor_physical_listing",first.instruction().toString());output.put("owner",sourceOwner);
   if(!c6000.C6000ExecutionPackets.parallelWithNext(currentProgram,first.instruction())){output.put("status","no_parallel_peer");anchors.add(output);return;}
   // Existing raw packet helper bounds the chain and refuses conflicting NOP generators.
   c6000.C6000ExecutionPackets.parallelBytes(currentProgram,toAddr(start));
   var prefix=C6000ExecutionPackets.issuePrefix(currentProgram,toAddr(start));int count=prefix.size()+1;boolean headerBased=C6000PacketContext.physicalDecodeFields(currentProgram,toAddr(start)).get("c_hdrpkt")==1;
   for(var prior:prefix){bytes(prior.getOffset(),width(prior.getOffset()));headerBased|=C6000PacketContext.physicalDecodeFields(currentProgram,prior).get("c_hdrpkt")==1;}
   long pc=next(start,firstWidth);Instruction previous=first.instruction();var local=new ArrayList<Prepared>();
   while(c6000.C6000ExecutionPackets.parallelWithNext(currentProgram,previous)){
    monitor.checkCancelled();if(++count>8)throw new IllegalArgumentException("oversized packet");int width=width(pc);headerBased|=C6000PacketContext.physicalDecodeFields(currentProgram,toAddr(pc)).get("c_hdrpkt")==1;if(pc+width>limit)throw new IllegalArgumentException("peer exceeds reviewed bound");var actual=currentProgram.getListing().getInstructionAt(toAddr(pc));
    if(actual!=null){if(actual.getLength()!=width||owner(pc)!=null&&!Objects.equals(owner(pc),sourceOwner))throw new IllegalArgumentException("defined peer extent/owner conflict");Long existingOwner=owner(pc);for(int k=0;k<width;k++)if(!Objects.equals(existingOwner,owner(pc+k)))throw new IllegalArgumentException("defined peer partial owner extent");peers.add(Map.of("address",pc,"width",width,"status","already_defined"));previous=parse(pc,true,false).instruction();}
    else{
     undefined(pc,width,sourceOwner);var fresh=parse(pc,true,true);var existing=parse(pc,false,true);
     if(!fresh.pcodeSha().equals(existing.pcodeSha())||!fresh.instruction().toString().equals(existing.instruction().toString()))throw new IllegalArgumentException("stored context disagrees with physical fresh parse");
     var row=new Candidate(pc,width,HexFormat.of().formatHex(bytes(pc,width)),existing.instruction().toString(),existing.pcodeSha(),existing.contextSha(),owner(pc));var value=new Prepared(row,existing);local.add(value);peers.add(Map.of("address",pc,"width",width,"status","eligible","listing",row.listing()));previous=fresh.instruction();
    }
    pc=next(pc,width);
   }
   if(count==8&&headerBased)throw new IllegalArgumentException("eight-instruction header-based packet");for(var candidate:local){var old=prepared.get(candidate.row().address());if(old!=null&&!old.row().equals(candidate.row()))throw new IllegalArgumentException("overlapping anchor plan disagreement");}for(var candidate:local)prepared.putIfAbsent(candidate.row().address(),candidate);output.put("status","proved_parallel_chain");output.put("end",pc);
  }catch(ghidra.util.exception.CancelledException cancelled){throw cancelled;}catch(Exception rejected){output.put("status","unresolved");output.put("reason",rejected.getCause()==null?rejected.toString():rejected.getCause().toString());}
  anchors.add(output);
 }
}
