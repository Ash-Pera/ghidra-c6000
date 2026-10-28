// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B 3.5 and 3.10.2/3.10.4: physical p bits prove same-EP peers, not a full delay window.
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.plugin.core.analysis.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;

/** Default: report only. Apply requires an unchanged reviewed report SHA and plan. Never follows flow. */
public class C6000RecoverParallelPeers extends GhidraScript {
 static final Gson JSON=new GsonBuilder().setPrettyPrinting().create();
 record Candidate(long address,int width,String bytes,String listing,String pcodeSha,String contextSha,Long owner) {}
 record Parsed(Instruction instruction,InstructionPrototype prototype,ProcessorContextImpl context,String pcodeSha,String contextSha) {}
 record Prepared(Candidate row,Parsed parsed) {}
 private long sourceStart,sourceEnd;
 private java.lang.reflect.Method physicalFields,physicalLength,issuePrefix;
 private final TreeMap<Long,Prepared> prepared=new TreeMap<>();
 private final List<Object> anchors=new ArrayList<>();
 String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
 String hash(String text)throws Exception{return hash(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));}
 byte[] bytes(long pc,int size)throws Exception{if(pc<sourceStart||size<0||pc+size>sourceEnd)throw new IllegalArgumentException("outside pinned source bounds");byte[] bytes=new byte[size];if(currentProgram.getMemory().getBytes(toAddr(pc),bytes)!=size)throw new IllegalArgumentException("short source read");return bytes;}
 void field(ProcessorContextImpl context,String name,int value){context.setRegisterValue(new RegisterValue(currentProgram.getRegister(name),BigInteger.valueOf(value)));}
 int width(long pc)throws Exception{return (Integer)physicalLength.invoke(null,currentProgram,toAddr(pc));}
 long next(long pc,int width)throws Exception{long result=pc+width;if((result&31)==28){int value=currentProgram.getMemory().getInt(toAddr(result));if((value>>>28)==14){bytes(result,4);result+=4;}}return result;}
 ProcessorContextImpl stored(long pc){var context=new ProcessorContextImpl(currentProgram.getLanguage());var value=currentProgram.getProgramContext().getRegisterValue(currentProgram.getLanguage().getContextBaseRegister(),toAddr(pc));if(value!=null)context.setRegisterValue(value);return context;}
 String pcode(Instruction instruction)throws Exception{var text=new StringBuilder();var code=instruction.getPcode();if(code.length==0&&!instruction.getMnemonicString().equals("NOP"))throw new IllegalArgumentException("empty/opaque p-code");int operationIndex=0;for(var op:code){int kind=op.getOpcode();if(Set.of(PcodeOp.UNIMPLEMENTED,PcodeOp.CALLOTHER,PcodeOp.CALL,PcodeOp.CALLIND,PcodeOp.RETURN,PcodeOp.BRANCHIND).contains(kind))throw new IllegalArgumentException("opaque/control p-code");if((kind==PcodeOp.BRANCH||kind==PcodeOp.CBRANCH)&&!op.getInput(0).isConstant())throw new IllegalArgumentException("external p-code branch");if(kind==PcodeOp.BRANCH||kind==PcodeOp.CBRANCH){int destination=operationIndex+(int)op.getInput(0).getOffset();if(destination<0||destination>code.length)throw new IllegalArgumentException("invalid internal p-code branch");}operationIndex++;text.append(kind).append(':');var nodes=new ArrayList<Varnode>();nodes.add(op.getOutput());nodes.addAll(Arrays.asList(op.getInputs()));for(var node:nodes){if(node==null)text.append("null");else text.append(node.getAddress().getAddressSpace().getName()).append('@').append(Long.toUnsignedString(node.getOffset(),16)).append('/').append(node.getSize());text.append(';');}text.append('\n');}return hash(text.toString());}
 Parsed parse(long pc,boolean physical,boolean peer)throws Exception{
  int width=width(pc);bytes(pc,width);var context=stored(pc);
  if(physical)for(var item:((Map<String,Integer>)physicalFields.invoke(null,currentProgram,toAddr(pc))).entrySet())field(context,item.getKey(),item.getValue());
  var memory=new DumbMemBufferImpl(currentProgram.getMemory(),toAddr(pc));var prototype=currentProgram.getLanguage().parse(memory,context,false);var instruction=new PseudoInstruction(currentProgram,toAddr(pc),prototype,memory,context);
  if(instruction.getLength()!=width)throw new IllegalArgumentException("stored/physical width mismatch");
  if(peer&&(instruction.getFlowType().isJump()||instruction.getFlowType().isCall()||instruction.getFlowType().isTerminal()))throw new IllegalArgumentException("control-flow peer requires separate review");
  String code=peer?pcode(instruction):"anchor";var base=currentProgram.getLanguage().getContextBaseRegister();var value=context.getRegisterValue(base);
  return new Parsed(instruction,prototype,context,code,hash(String.valueOf(value)));
 }
 Long owner(long pc){var function=currentProgram.getFunctionManager().getFunctionContaining(toAddr(pc));return function==null?null:function.getEntryPoint().getOffset();}
 void undefined(long pc,int size,Long sourceOwner)throws Exception{
  Long first=owner(pc);if(first!=null&&!first.equals(sourceOwner))throw new IllegalArgumentException("foreign owner");if(currentProgram.getFunctionManager().getFunctionAt(toAddr(pc))!=null)throw new IllegalArgumentException("function entry conflict");
  for(int k=0;k<size;k++){var at=toAddr(pc+k);if(currentProgram.getListing().getInstructionContaining(at)!=null||currentProgram.getListing().getDefinedDataContaining(at)!=null)throw new IllegalArgumentException("existing code/data overlap");if(!Objects.equals(first,owner(pc+k)))throw new IllegalArgumentException("partial owner extent");}
 }
 void inspect(JsonObject anchor)throws Exception{
  long start=anchor.get("address").getAsLong(),limit=anchor.get("allowed_end").getAsLong();var output=new LinkedHashMap<String,Object>();output.put("address",start);output.put("allowed_end",limit);var peers=new ArrayList<Object>();output.put("peers",peers);
  try{
   if(start<sourceStart||limit>sourceEnd||limit<=start||limit-start>64)throw new IllegalArgumentException("invalid anchor bound");var original=currentProgram.getListing().getInstructionAt(toAddr(start));if(original==null)throw new IllegalArgumentException("anchor is not a defined instruction");int firstWidth=width(start);if(original.getLength()!=firstWidth)throw new IllegalArgumentException("anchor physical extent differs");if(!HexFormat.of().formatHex(bytes(start,firstWidth)).equals(anchor.get("expected_bytes").getAsString()))throw new IllegalArgumentException("anchor bytes changed");var first=parse(start,true,false);Long sourceOwner=owner(start);output.put("anchor_listing",original.toString());output.put("anchor_physical_listing",first.instruction().toString());output.put("owner",sourceOwner);
   if(!c6000.C6000ExecutionPackets.parallelWithNext(currentProgram,first.instruction())){output.put("status","no_parallel_peer");anchors.add(output);return;}
   // Existing raw packet helper bounds the chain and refuses conflicting NOP generators.
   c6000.C6000ExecutionPackets.parallelBytes(currentProgram,toAddr(start));
   var prefix=(List<Address>)issuePrefix.invoke(null,currentProgram,toAddr(start));int count=prefix.size()+1;boolean headerBased=((Map<String,Integer>)physicalFields.invoke(null,currentProgram,toAddr(start))).get("c_hdrpkt")==1;
   for(var prior:prefix){bytes(prior.getOffset(),width(prior.getOffset()));headerBased|=((Map<String,Integer>)physicalFields.invoke(null,currentProgram,prior)).get("c_hdrpkt")==1;}
   long pc=next(start,firstWidth);Instruction previous=first.instruction();var local=new ArrayList<Prepared>();
   while(c6000.C6000ExecutionPackets.parallelWithNext(currentProgram,previous)){
    monitor.checkCancelled();if(++count>8)throw new IllegalArgumentException("oversized packet");int width=width(pc);headerBased|=((Map<String,Integer>)physicalFields.invoke(null,currentProgram,toAddr(pc))).get("c_hdrpkt")==1;if(pc+width>limit)throw new IllegalArgumentException("peer exceeds reviewed bound");var actual=currentProgram.getListing().getInstructionAt(toAddr(pc));
    if(actual!=null){if(actual.getLength()!=width||owner(pc)!=null&&!Objects.equals(owner(pc),sourceOwner))throw new IllegalArgumentException("defined peer extent/owner conflict");Long existingOwner=owner(pc);for(int k=0;k<width;k++)if(!Objects.equals(existingOwner,owner(pc+k)))throw new IllegalArgumentException("defined peer partial owner extent");peers.add(Map.of("address",pc,"width",width,"status","already_defined"));previous=parse(pc,true,false).instruction();}
    else{
     undefined(pc,width,sourceOwner);var fresh=parse(pc,true,true);var existing=parse(pc,false,true);
     if(!fresh.pcodeSha().equals(existing.pcodeSha())||!fresh.instruction().toString().equals(existing.instruction().toString()))throw new IllegalArgumentException("stored context disagrees with physical fresh parse");
     var row=new Candidate(pc,width,HexFormat.of().formatHex(bytes(pc,width)),existing.instruction().toString(),existing.pcodeSha(),existing.contextSha(),owner(pc));var value=new Prepared(row,existing);local.add(value);peers.add(Map.of("address",pc,"width",width,"status","eligible","listing",row.listing()));previous=fresh.instruction();
    }
    pc=next(pc,width);
   }
   if(count==8&&headerBased)throw new IllegalArgumentException("eight-instruction header-based packet");for(var candidate:local){var old=prepared.get(candidate.row().address());if(old!=null&&!old.row().equals(candidate.row()))throw new IllegalArgumentException("overlapping anchor plan disagreement");}for(var candidate:local)prepared.putIfAbsent(candidate.row().address(),candidate);output.put("status","proved_parallel_chain");output.put("end",pc);
  }catch(Exception rejected){output.put("status","unresolved");output.put("reason",rejected.getCause()==null?rejected.toString():rejected.getCause().toString());}
  anchors.add(output);
 }
 String ref(ghidra.program.model.symbol.Reference r){return r.getFromAddress()+"|"+r.getToAddress()+"|"+r.getOperandIndex()+"|"+r.getReferenceType()+"|"+r.getSource()+"|"+r.isPrimary()+"|"+r.getSymbolID();}
 SortedSet<String> references(){var rows=new TreeSet<String>();var it=currentProgram.getReferenceManager().getReferenceSourceIterator(currentProgram.getMemory().getAllInitializedAddressSet(),true);while(it.hasNext())for(var r:currentProgram.getReferenceManager().getReferencesFrom(it.next()))rows.add(ref(r));return rows;}
 SortedMap<String,String> functions(){var rows=new TreeMap<String,String>();var it=currentProgram.getFunctionManager().getFunctions(true);while(it.hasNext()){var f=it.next();rows.put(f.getEntryPoint().toString(),f.getName()+"|"+f.getBody()+"|"+f.getPrototypeString(true,false));}return rows;}
 SortedMap<String,String> comments(){var rows=new TreeMap<String,String>();var listing=currentProgram.getListing();var it=listing.getCommentAddressIterator(currentProgram.getMemory().getAllInitializedAddressSet(),true);while(it.hasNext()){var at=it.next();for(int kind=0;kind<5;kind++){String value=listing.getComment(kind,at);if(value!=null)rows.put(at+":"+kind,value);}}return rows;}
 SortedMap<Long,String> instructions(){var rows=new TreeMap<Long,String>();var it=currentProgram.getListing().getInstructions(new AddressSet(toAddr(sourceStart),toAddr(sourceEnd-1)),true);while(it.hasNext()){var i=it.next();rows.put(i.getAddress().getOffset(),i.getLength()+"|"+i+"|"+i.getFlowOverride()+"|"+i.isFallThroughOverridden()+"|"+i.getFallThrough()+"|"+i.getDelaySlotDepth());}return rows;}
 protected void run()throws Exception{
  var args=getScriptArgs();if(args.length!=2&&args.length!=4)throw new IllegalArgumentException("MANIFEST REPORT [apply REVIEW_SHA256]");boolean apply=args.length==4;if(apply&&!args[2].equals("apply"))throw new IllegalArgumentException("explicit apply mode required");var reportPath=Paths.get(args[1]);if(Paths.get(args[0]).toAbsolutePath().normalize().equals(reportPath.toAbsolutePath().normalize()))throw new IllegalArgumentException("manifest and report paths must differ");JsonObject reviewed=null;if(apply){byte[] reviewedBytes=Files.readAllBytes(reportPath);if(!hash(reviewedBytes).equals(args[3]))throw new IllegalArgumentException("review report SHA changed");reviewed=JsonParser.parseString(new String(reviewedBytes,java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();}
  byte[] input=Files.readAllBytes(Paths.get(args[0]));String manifestHash=hash(input);var manifest=JsonParser.parseString(new String(input,java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();if(manifest.get("schema").getAsInt()!=1||!manifest.get("language_id").getAsString().equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalArgumentException("manifest schema/language mismatch");var source=manifest.getAsJsonObject("source");sourceStart=source.get("start").getAsLong();int size=source.get("length").getAsInt();if(sourceStart<0||sourceStart>0xffffffffL||size<=0||size>16*1024*1024||(sourceStart&31)!=0||(size&31)!=0)throw new IllegalArgumentException("pinned full-fetch source bounds required");sourceEnd=sourceStart+size;if(sourceEnd>0x100000000L||!hash(bytes(sourceStart,size)).equals(source.get("sha256").getAsString()))throw new IllegalArgumentException("pinned source SHA mismatch");
  physicalFields=c6000.C6000PacketContext.class.getDeclaredMethod("physicalDecodeFields",Program.class,Address.class);physicalFields.setAccessible(true);physicalLength=c6000.C6000ExecutionPackets.class.getDeclaredMethod("instructionLengthAt",Program.class,Address.class);physicalLength.setAccessible(true);issuePrefix=c6000.C6000ExecutionPackets.class.getDeclaredMethod("issuePrefix",Program.class,Address.class);issuePrefix.setAccessible(true);
  long beforeMod=currentProgram.getModificationNumber();for(var row:manifest.getAsJsonArray("anchors"))inspect(row.getAsJsonObject());var candidates=prepared.values().stream().map(Prepared::row).toList();String planHash=hash(JSON.toJson(candidates));if(currentProgram.getModificationNumber()!=beforeMod)throw new AssertionError("report mutated program");
  var report=new LinkedHashMap<String,Object>();report.put("schema",1);report.put("mode",apply?"apply":"report");report.put("manifest_sha256",manifestHash);report.put("source_sha256",source.get("sha256").getAsString());report.put("plan_sha256",planHash);report.put("eligible_count",candidates.size());report.put("candidates",candidates);report.put("anchors",anchors);report.put("cleared_code_units",0);report.put("function_bodies_changed",false);report.put("context_writes",0);report.put("flow_followed",false);report.put("autoanalysis_run",false);
  if(apply){if(!reviewed.get("manifest_sha256").getAsString().equals(manifestHash)||!reviewed.get("plan_sha256").getAsString().equals(planHash))throw new IllegalArgumentException("reviewed plan changed");report.put("review_report_sha256",args[3]);var archive=reportPath.resolveSibling(reportPath.getFileName()+".reviewed-"+args[3]+".json");if(Files.exists(archive)){if(!hash(Files.readAllBytes(archive)).equals(args[3]))throw new IllegalArgumentException("review archive conflict");}else Files.copy(reportPath,archive);report.put("review_archive",archive.toString());var manager=AutoAnalysisManager.getAnalysisManager(currentProgram);if(manager.isAnalyzing())throw new IllegalArgumentException("apply requires idle auto-analysis");
   var savedFunctions=functions();var savedComments=comments();var savedRefs=references();var savedInstructions=instructions();
   boolean ok=manager.scheduleWorker(new AnalysisWorker(){public String getWorkerName(){return "Recover reviewed C6000 parallel peers";}public boolean analysisWorkerCallback(Program p,Object context,TaskMonitor task)throws Exception{
    int transaction=p.startTransaction("Create undefined reviewed parallel peers");boolean commit=false;try{if(!hash(bytes(sourceStart,(int)(sourceEnd-sourceStart))).equals(source.get("sha256").getAsString()))throw new IllegalArgumentException("source changed before transaction");for(var value:prepared.values()){task.checkCancelled();var row=value.row();if(!Objects.equals(owner(row.address()),row.owner()))throw new IllegalArgumentException("reviewed ownership changed");undefined(row.address(),row.width(),row.owner());if(!HexFormat.of().formatHex(bytes(row.address(),row.width())).equals(row.bytes()))throw new IllegalArgumentException("peer bytes changed");var fresh=parse(row.address(),true,true);var stored=parse(row.address(),false,true);if(!stored.contextSha().equals(row.contextSha())||!stored.pcodeSha().equals(row.pcodeSha())||!fresh.pcodeSha().equals(stored.pcodeSha()))throw new IllegalArgumentException("reviewed decode context changed");String contextBefore=String.valueOf(p.getProgramContext().getRegisterValue(p.getLanguage().getContextBaseRegister(),toAddr(row.address())));var ins=p.getListing().createInstruction(toAddr(row.address()),value.parsed().prototype(),new DumbMemBufferImpl(p.getMemory(),toAddr(row.address())),value.parsed().context(),0);if(ins.getLength()!=row.width()||!ins.toString().equals(row.listing())||!pcode(ins).equals(row.pcodeSha()))throw new AssertionError("created native decode differs from reviewed plan");if(!contextBefore.equals(String.valueOf(p.getProgramContext().getRegisterValue(p.getLanguage().getContextBaseRegister(),toAddr(row.address())))))throw new AssertionError("stored decode context changed");}
     if(!savedFunctions.equals(functions())||!savedComments.equals(comments())||!references().containsAll(savedRefs))throw new AssertionError("original annotation/reference/body drift");var after=instructions();for(var row:savedInstructions.entrySet())if(!Objects.equals(row.getValue(),after.get(row.getKey())))throw new AssertionError("existing instruction changed at "+Long.toHexString(row.getKey()));commit=true;return true;
    }finally{p.endTransaction(transaction,commit);}
   }},null,false,monitor);if(!ok)throw new AssertionError("apply worker failed");report.put("created_count",prepared.size());report.put("original_comments_preserved",true);report.put("original_references_preserved",true);report.put("original_instructions_preserved",true);
  }else{report.put("created_count",0);report.put("program_modification_unchanged",true);}
  Files.writeString(reportPath,JSON.toJson(report));println("C6000_PARALLEL_PEERS_OK mode="+(apply?"apply":"report")+" eligible="+prepared.size()+" created="+(apply?prepared.size():0));
 }
}
