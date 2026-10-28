// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Retain misplaced, code-verified switch overrides outside their former owner.
// No instruction, flow reference or function body is changed. Use on a comparison copy.
import c6000.C6000JumpTableAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;

public class C6000RepairSwitchOverrides extends GhidraScript {
 protected void run() throws Exception {
  MessageLog log=new MessageLog();
  int repaired=C6000JumpTableAnalyzer.repairDetachedOverrides(currentProgram,monitor,log);
  println("C6000_SWITCH_OVERRIDE_REPAIR repaired="+repaired);
  if(log.hasMessages())println(log.toString());
 }
}
