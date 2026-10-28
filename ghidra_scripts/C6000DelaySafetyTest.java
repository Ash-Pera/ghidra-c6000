// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Refuse nested control transfers, defined data and another function's entry, and oversized execute packets.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;
public class C6000DelaySafetyTest extends GhidraScript {
 protected void run()throws Exception{
  for(int n=0;n<6;n++){var at=toAddr(0x5000+n*0x100);currentProgram.getMemory().createInitializedBlock("refusal"+n,at,64,(byte)0,monitor,false);currentProgram.getMemory().setInt(at,(3<<18)|0x362);currentProgram.getMemory().setInt(at.add(4),n==0?0x10000010:0);}
  // Nine instructions chained in one execute packet exceed the CPU's eight units.
  for(int n=0;n<9;n++)currentProgram.getMemory().setInt(toAddr(0x5300+n*4),n==0?((3<<18)|0x363):n==8?0:1);
  currentProgram.getMemory().setInt(toAddr(0x5404),0x20000000|0x264|(4<<18)|(5<<23));
  currentProgram.getMemory().setInt(toAddr(0x541c),0xe0100000);
  currentProgram.getMemory().setInt(toAddr(0x5504),0x1e000); // IDLE has no finite wakeup bound.
  c6000.C6000PacketContext.prime(currentProgram,monitor);
  for(int n=0;n<6;n++){var at=toAddr(0x5000+n*0x100);currentProgram.getProgramContext().setValue(currentProgram.getRegister("c_branch_terminal"),at,at,BigInteger.ONE);new DisassembleCommand(at,null,false).applyTo(currentProgram,monitor);currentProgram.getFunctionManager().createFunction("refuse"+n,at,new AddressSet(at,at.add(3)),SourceType.USER_DEFINED);
   if(n==0){new DisassembleCommand(at.add(4),null,false).applyTo(currentProgram,monitor);currentProgram.getListing().getInstructionAt(at.add(4)).setFlowOverride(FlowOverride.CALL);}
   if(n==1)createData(at.add(4),ghidra.program.model.data.DWordDataType.dataType);
   if(n==2){new DisassembleCommand(at.add(4),null,false).applyTo(currentProgram,monitor);currentProgram.getFunctionManager().createFunction("different_owner",at.add(4),new AddressSet(at.add(4),at.add(7)),SourceType.USER_DEFINED);}
  }
  c6000.C6000DelaySlots.recover(currentProgram,monitor,new ghidra.app.util.importer.MessageLog());
  for(int n=0;n<6;n++){var at=toAddr(0x5000+n*0x100);var i=currentProgram.getListing().getInstructionAt(at);var f=currentProgram.getFunctionManager().getFunctionAt(at);if(i.getDelaySlotDepth()!=0||f.getBody().getNumAddresses()!=4)throw new AssertionError("Unsafe recovery "+n);}
  println("C6000_DELAY_SAFETY_OK cases=6");
 }
}
