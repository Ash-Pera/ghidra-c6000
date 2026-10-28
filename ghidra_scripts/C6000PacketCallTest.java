// SPDX-License-Identifier: Apache-2.0
// @category C6000
// CALLP packet companions, pre-write link reads and next-packet return address.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import c6000.C6000PacketContext;
import java.nio.file.*;
public class C6000PacketCallTest extends GhidraScript {
 protected void run()throws Exception{
  C6000PacketContext.prime(currentProgram,monitor);
  currentProgram.getMemory().createInitializedBlock("results",toAddr(0x8000),4096,(byte)0,monitor,false);
  int checked=0;
  for(String row:Files.readAllLines(Paths.get(getScriptArgs()[0]))){var f=row.split("\\t");var at=toAddr(Long.parseUnsignedLong(f[0],16));long target=Long.parseUnsignedLong(f[2],16),link=Long.parseUnsignedLong(f[3],16);new DisassembleCommand(at,null,false).applyTo(currentProgram,monitor);c6000.C6000DelaySlots.recover(currentProgram,monitor,new ghidra.app.util.importer.MessageLog());var ins=currentProgram.getListing().getInstructionAt(at);if(ins==null||!ins.getFlowType().isCall())throw new AssertionError(f[1]+": "+ins);
   println("CALL "+f[1]+" "+ins+" bytes="+ins.getPrototype().getDelaySlotByteCount()+" depth="+ins.getDelaySlotDepth()+" context="+currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_flow_delay"),at,false));
   for(var dbg:currentProgram.getListing().getInstructions(new ghidra.program.model.address.AddressSet(at,at.add(12)),true))println("SLOT "+dbg.getAddress()+" "+dbg+" delay="+dbg.isInDelaySlot());
   if(!toAddr(link).equals(ins.getFallThrough()))throw new AssertionError(f[1]+": fallthrough "+ins.getFallThrough()+" expected "+toAddr(link));
   var arithmetic=ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());
   var state=new ghidra.pcode.exec.BytesPcodeExecutorState(currentProgram.getLanguage(),ghidra.pcode.exec.PcodeStateCallbacks.NONE);
   var reason=ghidra.pcode.exec.PcodeExecutorStatePiece.Reason.INSPECT;
   state.setVar(currentProgram.getRegister("AMR"),arithmetic.fromConst(0,4));
   state.setVar(currentProgram.getRegister("A4"),arithmetic.fromConst(0x8000,4));
   for(String reg:new String[]{"A3","B3"})state.setVar(currentProgram.getRegister(reg),arithmetic.fromConst(0x76543210,4));
   state.setVar(toAddr(0x8000),32,false,new byte[32]);
   var executor=new ghidra.pcode.exec.PcodeExecutor<byte[]>((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage()), state, ghidra.pcode.exec.PcodeExecutorStatePiece.Reason.EXECUTE_READ);
   executor.execute(ghidra.pcode.exec.PcodeProgram.fromInstruction(ins,true),ghidra.pcode.exec.PcodeUseropLibrary.nil());
   for(String reg:new String[]{"PC",f[4]}){long actual=arithmetic.toLong(state.getVar(currentProgram.getRegister(reg),reason),ghidra.pcode.exec.PcodeArithmetic.Purpose.INSPECT);long expected=reg.equals("PC")?target:link;if(actual!=expected)throw new AssertionError(f[1]+": "+reg+"="+Long.toHexString(actual)+" expected="+Long.toHexString(expected));}
   for(int n:new int[]{0,7}){long actual=arithmetic.toLong(state.getVar(toAddr(0x8000+4*n),4,false,reason),ghidra.pcode.exec.PcodeArithmetic.Purpose.INSPECT);long expected=n==0&&f[5].equals("1")?0x76543210:0;if(actual!=expected)throw new AssertionError(f[1]+": packet/guard store "+n+"="+Long.toHexString(actual));}
   checked++;
  }
  println("C6000_PACKET_CALL_OK cases="+checked);
 }
}
