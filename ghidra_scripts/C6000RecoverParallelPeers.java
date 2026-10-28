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
 private long sourceStart,sourceEnd;
 private c6000.C6000ParallelPeers proof;
 private Collection<c6000.C6000ParallelPeers.Prepared> prepared;
 private List<Object> anchors;
 String hash(byte[] value)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));}
 String hash(String value)throws Exception{return hash(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));}
 byte[] bytes(long pc,int size)throws Exception{if(pc<sourceStart||size<0||pc+size>sourceEnd)throw new IllegalArgumentException("outside pinned source bounds");byte[] value=new byte[size];if(currentProgram.getMemory().getBytes(toAddr(pc),value)!=size)throw new IllegalArgumentException("short source read");return value;}
 String ref(ghidra.program.model.symbol.Reference r){return r.getFromAddress()+"|"+r.getToAddress()+"|"+r.getOperandIndex()+"|"+r.getReferenceType()+"|"+r.getSource()+"|"+r.isPrimary()+"|"+r.getSymbolID();}
 SortedSet<String> references(){var rows=new TreeSet<String>();var it=currentProgram.getReferenceManager().getReferenceSourceIterator(currentProgram.getMemory().getAllInitializedAddressSet(),true);while(it.hasNext())for(var r:currentProgram.getReferenceManager().getReferencesFrom(it.next()))rows.add(ref(r));return rows;}
 SortedMap<String,String> functions(){var rows=new TreeMap<String,String>();var it=currentProgram.getFunctionManager().getFunctions(true);while(it.hasNext()){var f=it.next();rows.put(f.getEntryPoint().toString(),f.getName()+"|"+f.getBody()+"|"+f.getPrototypeString(true,false));}return rows;}
 SortedMap<String,String> comments(){var rows=new TreeMap<String,String>();var listing=currentProgram.getListing();var it=listing.getCommentAddressIterator(currentProgram.getMemory().getAllInitializedAddressSet(),true);while(it.hasNext()){var at=it.next();for(int kind=0;kind<5;kind++){String value=listing.getComment(kind,at);if(value!=null)rows.put(at+":"+kind,value);}}return rows;}
 SortedMap<Long,String> instructions(){var rows=new TreeMap<Long,String>();var it=currentProgram.getListing().getInstructions(new AddressSet(toAddr(sourceStart),toAddr(sourceEnd-1)),true);while(it.hasNext()){var i=it.next();rows.put(i.getAddress().getOffset(),i.getLength()+"|"+i+"|"+i.getFlowOverride()+"|"+i.isFallThroughOverridden()+"|"+i.getFallThrough()+"|"+i.getDelaySlotDepth());}return rows;}
 protected void run()throws Exception{
  var args=getScriptArgs();if(args.length!=2&&args.length!=4)throw new IllegalArgumentException("MANIFEST REPORT [apply REVIEW_SHA256]");boolean apply=args.length==4;if(apply&&!args[2].equals("apply"))throw new IllegalArgumentException("explicit apply mode required");var reportPath=Paths.get(args[1]);if(Paths.get(args[0]).toAbsolutePath().normalize().equals(reportPath.toAbsolutePath().normalize()))throw new IllegalArgumentException("manifest and report paths must differ");JsonObject reviewed=null;if(apply){byte[] reviewedBytes=Files.readAllBytes(reportPath);if(!hash(reviewedBytes).equals(args[3]))throw new IllegalArgumentException("review report SHA changed");reviewed=JsonParser.parseString(new String(reviewedBytes,java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();}
  byte[] input=Files.readAllBytes(Paths.get(args[0]));String manifestHash=hash(input);var manifest=JsonParser.parseString(new String(input,java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();if(manifest.get("schema").getAsInt()!=1||!manifest.get("language_id").getAsString().equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalArgumentException("manifest schema/language mismatch");var source=manifest.getAsJsonObject("source");sourceStart=source.get("start").getAsLong();int size=source.get("length").getAsInt();if(sourceStart<0||sourceStart>0xffffffffL||size<=0||size>16*1024*1024||(sourceStart&31)!=0||(size&31)!=0)throw new IllegalArgumentException("pinned full-fetch source bounds required");sourceEnd=sourceStart+size;if(sourceEnd>0x100000000L||!hash(bytes(sourceStart,size)).equals(source.get("sha256").getAsString()))throw new IllegalArgumentException("pinned source SHA mismatch");
  proof=new c6000.C6000ParallelPeers(currentProgram,monitor,sourceStart,sourceEnd);
  long beforeMod=currentProgram.getModificationNumber();for(var row:manifest.getAsJsonArray("anchors"))proof.inspect(row.getAsJsonObject());prepared=proof.candidates();anchors=proof.reports();var candidates=prepared.stream().map(c6000.C6000ParallelPeers.Prepared::row).toList();String planHash=hash(JSON.toJson(candidates));if(currentProgram.getModificationNumber()!=beforeMod)throw new AssertionError("report mutated program");
  var report=new LinkedHashMap<String,Object>();report.put("schema",1);report.put("mode",apply?"apply":"report");report.put("manifest_sha256",manifestHash);report.put("source_sha256",source.get("sha256").getAsString());report.put("plan_sha256",planHash);report.put("eligible_count",candidates.size());report.put("candidates",candidates);report.put("anchors",anchors);report.put("cleared_code_units",0);report.put("function_bodies_changed",false);report.put("context_writes",0);report.put("flow_followed",false);report.put("autoanalysis_run",false);
  if(apply){if(!reviewed.get("manifest_sha256").getAsString().equals(manifestHash)||!reviewed.get("plan_sha256").getAsString().equals(planHash))throw new IllegalArgumentException("reviewed plan changed");report.put("review_report_sha256",args[3]);var archive=reportPath.resolveSibling(reportPath.getFileName()+".reviewed-"+args[3]+".json");if(Files.exists(archive)){if(!hash(Files.readAllBytes(archive)).equals(args[3]))throw new IllegalArgumentException("review archive conflict");}else Files.copy(reportPath,archive);report.put("review_archive",archive.toString());var manager=AutoAnalysisManager.getAnalysisManager(currentProgram);if(manager.isAnalyzing())throw new IllegalArgumentException("apply requires idle auto-analysis");
   var savedFunctions=functions();var savedComments=comments();var savedRefs=references();var savedInstructions=instructions();
   boolean ok=manager.scheduleWorker(new AnalysisWorker(){public String getWorkerName(){return "Recover reviewed C6000 parallel peers";}public boolean analysisWorkerCallback(Program p,Object context,TaskMonitor task)throws Exception{
    int transaction=p.startTransaction("Create undefined reviewed parallel peers");boolean commit=false;try{if(!hash(bytes(sourceStart,(int)(sourceEnd-sourceStart))).equals(source.get("sha256").getAsString()))throw new IllegalArgumentException("source changed before transaction");for(var value:prepared){task.checkCancelled();var row=value.row();if(!Objects.equals(proof.owner(row.address()),row.owner()))throw new IllegalArgumentException("reviewed ownership changed");proof.undefined(row.address(),row.width(),row.owner());if(!HexFormat.of().formatHex(bytes(row.address(),row.width())).equals(row.bytes()))throw new IllegalArgumentException("peer bytes changed");var fresh=proof.parse(row.address(),true,true);var stored=proof.parse(row.address(),false,true);if(!stored.contextSha().equals(row.contextSha())||!stored.pcodeSha().equals(row.pcodeSha())||!fresh.pcodeSha().equals(stored.pcodeSha()))throw new IllegalArgumentException("reviewed decode context changed");String contextBefore=String.valueOf(p.getProgramContext().getRegisterValue(p.getLanguage().getContextBaseRegister(),toAddr(row.address())));var ins=p.getListing().createInstruction(toAddr(row.address()),value.parsed().prototype(),new DumbMemBufferImpl(p.getMemory(),toAddr(row.address())),value.parsed().context(),0);if(ins.getLength()!=row.width()||!ins.toString().equals(row.listing())||!proof.pcode(ins).equals(row.pcodeSha()))throw new AssertionError("created native decode differs from reviewed plan");if(!contextBefore.equals(String.valueOf(p.getProgramContext().getRegisterValue(p.getLanguage().getContextBaseRegister(),toAddr(row.address())))))throw new AssertionError("stored decode context changed");}
     if(!savedFunctions.equals(functions())||!savedComments.equals(comments())||!references().containsAll(savedRefs))throw new AssertionError("original annotation/reference/body drift");var after=instructions();for(var row:savedInstructions.entrySet())if(!Objects.equals(row.getValue(),after.get(row.getKey())))throw new AssertionError("existing instruction changed at "+Long.toHexString(row.getKey()));commit=true;return true;
    }finally{p.endTransaction(transaction,commit);}
   }},null,false,monitor);if(!ok)throw new AssertionError("apply worker failed");report.put("created_count",prepared.size());report.put("original_comments_preserved",true);report.put("original_references_preserved",true);report.put("original_instructions_preserved",true);
  }else{report.put("created_count",0);report.put("program_modification_unchanged",true);}
  Files.writeString(reportPath,JSON.toJson(report));println("C6000_PARALLEL_PEERS_OK mode="+(apply?"apply":"report")+" eligible="+prepared.size()+" created="+(apply?prepared.size():0));
 }
}
