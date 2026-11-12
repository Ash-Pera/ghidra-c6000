// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check shared call tails whose call or tail is in a staged packet (tests/fixtures/shared-tail-packet.py).
// Run as preScript with "prepare", then as postScript with no arguments.

import java.math.BigInteger;

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class C6000SharedTailPacketTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x10c0L, 0x1000L, 0x1060L };
	private static final String[] NAMES = { "callee", "pktowner", "pkttail" };
	private int checks;

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			for (int i = 0; i < ENTRIES.length; i++) {
				disassemble(toAddr(ENTRIES[i]));
				createFunction(toAddr(ENTRIES[i]), NAMES[i]);
			}
			return;
		}
		// Preconditions: both packets are staged, and both tails are carried.
		field(0x100cL, "c_pkt_active", 1); field(0x100cL, "c_pkt_branch_end", 1); field(0x100cL, "c_pkt_commit0", 11);
		field(0x1084L, "c_pkt_active", 1); field(0x1084L, "c_pkt_end", 1); field(0x1084L, "c_pkt_commit0", 5);
		carried(0x1020L, 0x100cL, 0x1030L, 0x102cL);
		carried(0x1084L, 0x106cL, 0x1094L, 0x1090L);
		// The inert owning call still commits its packet's staged A10.
		Instruction owner = getInstructionAt(toAddr(0x100cL));
		if (commit(owner, "A10") < 0) throw new AssertionError("inert branch lost its packet commit of A10: " + pcode(owner));
		checks++;
		// The carried call follows the packet's commit of A4, its argument.
		Instruction carrier = getInstructionAt(toAddr(0x1084L));
		int a4 = commit(carrier, "A4"), call = -1;
		PcodeOp[] ops = carrier.getPcode();
		for (int i = 0; i < ops.length; i++) if (ops[i].getOpcode() == PcodeOp.CALL || ops[i].getOpcode() == PcodeOp.CALLIND) call = i;
		if (a4 < 0 || call < a4) throw new AssertionError("carried call before its packet's commit of A4: " + pcode(carrier));
		checks++;
		loopCalls(0x1000L);
		loopCalls(0x1060L);
		println("C6000_SHARED_TAIL_PACKET_OK checks=" + checks);
	}

	private void field(long at, String name, long want) {
		BigInteger v = currentProgram.getProgramContext().getValue(currentProgram.getRegister(name), toAddr(at), false);
		if (v == null || v.longValue() != want) throw new AssertionError(name + " at " + toAddr(at) + " is " + v + ", want " + want);
		checks++;
	}

	/** Index of the p-code op that copies the register's packet shadow into it, else -1. */
	private int commit(Instruction insn, String register) {
		var reg = currentProgram.getRegister(register).getAddress();
		var shadow = currentProgram.getRegister("C6000_PKT_" + register).getAddress();
		PcodeOp[] ops = insn.getPcode();
		for (int i = 0; i < ops.length; i++) {
			Varnode out = ops[i].getOutput();
			if (out != null && out.getAddress().equals(reg) && ops[i].getOpcode() == PcodeOp.COPY &&
				ops[i].getInput(0).getAddress().equals(shadow)) return i;
		}
		return -1;
	}

	private static String pcode(Instruction insn) {
		return insn + " " + java.util.Arrays.toString(insn.getPcode());
	}

	/** As C6000SharedTailTest: the tail instruction calls callee; the issuing branches are inert; the jump keeps its window. */
	private void carried(long tail, long first, long second, long jump) {
		Instruction t = getInstructionAt(toAddr(tail)), a = getInstructionAt(toAddr(first)), b = getInstructionAt(toAddr(second)),
			j = getInstructionAt(toAddr(jump));
		if (t == null || !t.getFlowType().isCall() || t.getFlows().length != 1 || !t.getFlows()[0].equals(toAddr(0x10c0L)))
			throw new AssertionError("tail at " + toAddr(tail) + ": " + t + (t == null ? "" : " " + t.getFlowType()));
		for (Instruction i : new Instruction[] { a, b })
			if (i == null || i.getFlowType().isCall() || i.getFlowType().isJump() || i.getPrototype().getDelaySlotByteCount() != 0)
				throw new AssertionError("issuing branch still transfers: " + i);
		if (j == null || j.getPrototype().getDelaySlotByteCount() == 0)
			throw new AssertionError("jump at " + toAddr(jump) + ": " + j);
		checks++;
	}

	private void loopCalls(long entry) throws Exception {
		Function f = getFunctionAt(toAddr(entry));
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null)
				throw new AssertionError("decompile failed: " + (result == null ? "null" : result.getErrorMessage()));
			String c = result.getDecompiledFunction().getC();
			int loop = Math.min(c.indexOf("while") < 0 ? c.length() : c.indexOf("while"), c.indexOf("do {") < 0 ? c.length() : c.indexOf("do {"));
			if (loop == c.length() || c.lastIndexOf("callee(") < loop) throw new AssertionError(f.getName() + " has no call in its loop:\n" + c);
			checks++;
		}
		finally {
			decompiler.dispose();
		}
	}
}
