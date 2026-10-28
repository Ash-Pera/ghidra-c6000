// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B D-7/D-9/D-10 fixed A0/A1/B0/B1 destination under either header RS.
import java.nio.file.*;
import java.util.*;
import com.google.gson.Gson;
import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.pcode.PcodeOp;

public class C6000CompactCompareDestinationTest extends GhidraScript {
 static class Case {String operation,mnemonic,source1,source2,destination,shadow;int immediate;long[][] checks;}
 void equal(Object expected,Object actual,String label){if(!Objects.equals(expected,actual))throw new AssertionError(label+" expected="+expected+" actual="+actual);}
 protected void run()throws Exception{
  C6000PacketContext.prime(currentProgram,monitor);int count=0,executed=0;var gson=new Gson();
  for(String line:Files.readAllLines(Paths.get(getScriptArgs()[0]))){
   Case c=gson.fromJson(line,Case.class);var address=toAddr(0x1000L+32L*count);
   new DisassembleCommand(address,null,false).applyTo(currentProgram,monitor);
   var insn=currentProgram.getListing().getInstructionAt(address);if(insn==null)throw new AssertionError("Missing "+address);
   equal(2,insn.getLength(),address+" width");equal(c.mnemonic,insn.getMnemonicString(),address+" mnemonic");
   equal(c.source2,insn.getRegister(1).getName(),address+" source2");equal(c.destination,insn.getRegister(2).getName(),address+" fixed-low destination");
   if(c.source1==null)equal((long)c.immediate,insn.getScalar(0).getUnsignedValue(),address+" immediate");
   else equal(c.source1,insn.getRegister(0).getName(),address+" source1");
   for(var op:insn.getPcode())if(op.getOpcode()==PcodeOp.CALLOTHER)throw new AssertionError("Opaque comparison "+address);
   var emulator=new EmulatorHelper(currentProgram);
   try{for(long[] check:c.checks){
    emulator.writeRegister(c.destination,0x11223344L);emulator.writeRegister(c.shadow,0x55667788L);
    if(c.source1!=null)emulator.writeRegister(c.source1,check[0]);emulator.writeRegister(c.source2,check[1]);
    long shadow=emulator.readRegister(c.shadow).longValue()&0xffffffffL;
    emulator.writeRegister("CSR",0x2468L);emulator.getEmulator().setExecuteAddress(address.getOffset());
    if(!emulator.step(monitor))throw new AssertionError(emulator.getLastError());
    equal(check[2],emulator.readRegister(c.destination).longValue()&0xffffffffL,address+" result");
    equal(shadow,emulator.readRegister(c.shadow).longValue()&0xffffffffL,address+" high register preserved");
    equal(0x2468L,emulator.readRegister("CSR").longValue(),address+" CSR preserved");executed++;
   }}finally{emulator.dispose();}count++;
  }
  println("C6000_COMPACT_COMPARE_DESTINATION_OK cases="+count+" executed="+executed);
 }
}
