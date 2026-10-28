// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Synthetic full32 display, move semantics, exact form and packet-context checks.
import java.nio.file.*;
import java.util.*;
import c6000.C6000EncodingInfo;
import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.pcode.PcodeOp;
public class C6000Full32EncodingInfoTest extends GhidraScript {
 void equal(Object expected,Object actual,String label){if(!Objects.equals(expected,actual))throw new AssertionError(label+" expected="+expected+" actual="+actual);}
 Integer number(String text){return text.equals("-")?null:Integer.valueOf(text);}
 protected void run() throws Exception {
  C6000PacketContext.prime(currentProgram,monitor);int checked=0,executed=0;
  for(String row:Files.readAllLines(Paths.get(getScriptArgs()[0]))){
   String[] f=row.split("\\t");long offset=0x1000L+32L*Integer.parseInt(f[0]);var address=toAddr(offset);
   new DisassembleCommand(address,null,false).applyTo(currentProgram,monitor);
   var insn=currentProgram.getListing().getInstructionAt(address);if(insn==null)throw new AssertionError("missing "+address);
   equal(4,insn.getLength(),address+" width");equal(f[1],insn.getMnemonicString(),address+" mnemonic");
   var info=C6000EncodingInfo.describe(insn);equal(4,info.instructionWidth(),address+" metadata width");
   equal(f[2],info.addressForm().toString(),address+" address form");equal(number(f[3]),info.encodedOffset(),address+" offset");
   equal(f[4].equals("-")?null:f[4],info.baseRegister(),address+" base");equal(number(f[5]),info.offsetScaleBytes(),address+" scale");
   equal(number(f[6]),info.pcRelativeScaleBytes(),address+" branch scale");equal(f[7].equals("1"),info.packet().headerBased(),address+" header");
   if(info.packet().headerBased()) {
    var headerAt=toAddr(info.packet().address()+28);
    new DisassembleCommand(headerAt,new ghidra.program.model.address.AddressSet(headerAt,headerAt.add(3)),false).applyTo(currentProgram,monitor);
   }
   if(f[2].equals("REGISTER"))equal("B5",info.offsetRegister(),address+" offset register");
   if(!f[8].equals("metadata")){
    for(var op:insn.getPcode())if(op.getOpcode()==PcodeOp.CALLOTHER)throw new AssertionError("opaque move/zero "+address);
    if(f[8].equals("move")){
     equal(3,insn.getNumOperands(),address+" primitive operands");int zeroOperand=insn.getMnemonicString().contains("ADD.D")?1:0;
     equal(0L,insn.getScalar(zeroOperand).getSignedValue(),address+" explicit zero");
     equal(f[9],insn.getRegister(1-zeroOperand).getName(),address+" source bank");
     var copy=C6000EncodingInfo.registerCopySource(insn);
     equal(insn.getMnemonicString().startsWith("[")?null:f[9],copy==null?null:copy.getName(),address+" copy-recovery source");
     String unitBank=insn.getMnemonicString().contains("1")?"A":"B";
     equal(!f[9].startsWith(unitBank),info.crossPath(),address+" known move cross path");
    }
    var emulator=new EmulatorHelper(currentProgram);
    try{
     emulator.writeRegister(f[10],0x11223344L);emulator.writeRegister(f[9],0x89abcdefL);emulator.writeRegister("B0",Long.parseLong(f[12]));
     emulator.writeRegister("FADCR",0x06410641L);emulator.writeRegister("FMCR",0x06250625L);emulator.writeRegister("CSR",0x2468L);
     emulator.getEmulator().setExecuteAddress(offset);if(!emulator.step(monitor))throw new AssertionError(emulator.getLastError());
     equal(Long.parseUnsignedLong(f[11],16),emulator.readRegister(f[10]).longValue()&0xffffffffL,address+" result");
     equal(0x06410641L,emulator.readRegister("FADCR").longValue(),address+" FADCR unchanged");equal(0x06250625L,emulator.readRegister("FMCR").longValue(),address+" FMCR unchanged");equal(0x2468L,emulator.readRegister("CSR").longValue(),address+" CSR unchanged");
    }finally{emulator.dispose();}executed++;
   }
   checked++;
  }
  int headers=0;
  for(var header:currentProgram.getListing().getInstructions(true))if(header.getMnemonicString().equals("CPKT")) {
   headers++;var info=c6000.C6000EncodingInfo.describe(header);
   if(info.predicateRegister()!=null||info.parallelNext()!=null)throw new AssertionError("Header described as an executable opcode");
  }
  if(headers==0)throw new AssertionError("No header metadata checked");
  println("C6000_FULL32_ENCODING_INFO_OK cases="+checked+" executed="+executed);
 }
}
