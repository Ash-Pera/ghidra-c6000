// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check branches through a copy of B3 in a tests/fixtures/link-copy-return.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class C6000LinkCopyReturnTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1020L, 0x1040L, 0x1060L, 0x1080L, 0x10a0L, 0x10c0L, 0x10e0L, 0x1100L, 0x1120L };
	private static final String[] NAMES = { "copyret", "addret", "notb3", "twowr", "stale", "aret", "amv", "abad", "atwo", "acall" };

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
		// Known-good: B3 copied before any branch or B3 write, and B9 has no other writer.
		returns(0x100cL, 0x1010L);
		returns(0x1024L, 0x1028L);
		// Known-good: an A-side copy branched through the cross path (B .S2X A2).
		returns(0x10a8L, 0x10acL);
		returns(0x10c4L, 0x10c8L);
		// Known-bad: another register's copy, a second writer, B3 rewritten before the copy, a call between.
		for (long at : new long[] { 0x1044L, 0x1068L, 0x108cL, 0x10e4L, 0x1108L, 0x1134L }) {
			Instruction b = getInstructionAt(toAddr(at));
			if (b == null || b.getFlowOverride() == FlowOverride.RETURN) {
				throw new AssertionError("not a return at " + toAddr(at) + ": " + describe(b));
			}
		}
		println("C6000_LINK_COPY_RETURN_OK checks=10");
	}

	/** A RETURN after its window: the A4 write in slot precedes the RETURN op. */
	private void returns(long at, long slot) {
		Instruction b = getInstructionAt(toAddr(at));
		Instruction s = getInstructionAt(toAddr(slot));
		if (b == null || b.getFlowOverride() != FlowOverride.RETURN || !b.getFlowType().isTerminal() ||
			s == null || !s.isInDelaySlot()) {
			throw new AssertionError("return at " + toAddr(at) + ": " + describe(b) + "; slot " + s);
		}
		PcodeOp[] ops = b.getPcode(true);
		int ret = -1, a4 = -1;
		long offset = currentProgram.getRegister("A4").getOffset();
		for (int i = 0; i < ops.length; i++) {
			Varnode out = ops[i].getOutput();
			if (ops[i].getOpcode() == PcodeOp.RETURN) ret = i;
			if (out != null && out.isRegister() && out.getOffset() == offset) a4 = i;
		}
		if (ret < 0 || a4 < 0 || a4 > ret) throw new AssertionError("p-code order at " + toAddr(at) + ": " + describe(b));
	}

	private static String describe(Instruction i) {
		return i == null ? "null" : i + " flow=" + i.getFlowType() + " override=" + i.getFlowOverride() +
			" depth=" + i.getDelaySlotDepth();
	}
}
