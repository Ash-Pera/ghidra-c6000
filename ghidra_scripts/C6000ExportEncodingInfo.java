// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Export structured encoding forms. Usage: <output.jsonl> [start end].
import c6000.C6000EncodingInfo;
import com.google.gson.Gson;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import java.nio.file.*;
import java.util.*;
public class C6000ExportEncodingInfo extends GhidraScript {
 protected void run() throws Exception {
  String[] args=getScriptArgs();if(args.length!=1&&args.length!=3)throw new IllegalArgumentException("output.jsonl [start end]");
  var instructions=args.length==3?currentProgram.getListing().getInstructions(new AddressSet(toAddr(args[1]),toAddr(args[2])),true):currentProgram.getListing().getInstructions(true);
  Gson gson=new Gson();int count=0;
  try(var out=Files.newBufferedWriter(Paths.get(args[0]))){while(instructions.hasNext()){monitor.checkCancelled();var insn=instructions.next();Map<String,Object> row=new LinkedHashMap<>();row.put("address",insn.getAddress().toString());row.put("listing",insn.toString());row.put("encoding",C6000EncodingInfo.describe(insn));out.write(gson.toJson(row));out.newLine();count++;}}
  println("C6000_ENCODING_INFO_EXPORTED instructions="+count);
 }
}
