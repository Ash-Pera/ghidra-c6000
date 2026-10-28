// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Switch a comparison copy to concise floating-point p-code for reading.
// This changes arithmetic modeling: floating-point flags and special rounding
// are approximate in this language. Keep the default-language original for
// instruction-level semantic checks and emulation. Does not run auto-analysis.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.*;

public class C6000UseAnalysisLanguage extends GhidraScript {
 protected void run() throws Exception {
  String old=currentProgram.getLanguageID().toString();
  if(!old.startsWith("C6000:"))throw new IllegalArgumentException("Expected C6000 program");
  String[] parts=old.split(":");
  String id="C6000:"+parts[1]+":"+parts[2]+":analysis";
  if(old.equals(id)){println("C6000_ANALYSIS_LANGUAGE already="+id);return;}
  currentProgram.setLanguage(getLanguage(new LanguageID(id)),currentProgram.getCompilerSpec().getCompilerSpecID(),false,monitor);
  println("C6000_ANALYSIS_LANGUAGE "+old+" -> "+currentProgram.getLanguageID());
 }
}
