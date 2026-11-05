// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check B B3 calls (upstream #39) in a tests/fixtures/b3-call.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class C6000B3CallTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1040L, 0x1080L, 0x10a0L };
	private static final String[] NAMES = { "viaptr", "direct", "other", "callee" };

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
		// Known-good: the slots set B3 to the window end, so B B3 is a call there (SPRUFE8B 4.2.6, B).
		call(0x1008L, 0x1000L, 0x1018L, null);
		call(0x104cL, 0x1040L, 0x105cL, 0x10a0L);
		// Known-bad: B3 restored by a load, set elsewhere, or untouched: returns.
		for (long at : new long[] { 0x1024L, 0x1068L, 0x1080L, 0x10a4L }) {
			Instruction b = getInstructionAt(toAddr(at));
			if (b == null || b.getFlowOverride() != FlowOverride.RETURN || !b.getFlowType().isTerminal()) {
				throw new AssertionError("return at " + toAddr(at) + ": " + describe(b));
			}
		}
		println("C6000_B3_CALL_OK checks=6");
	}

	private void call(long at, long caller, long ret, Long callee) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || b.getFlowOverride() != FlowOverride.CALL || !b.getFlowType().isCall() ||
			b.getFlowType().isTerminal() || !toAddr(ret).equals(b.getFallThrough())) {
			throw new AssertionError("call at " + toAddr(at) + ": " + describe(b));
		}
		Instruction last = getInstructionAt(toAddr(ret - 4));
		if (last == null || !last.isInDelaySlot() || getFunctionContaining(toAddr(ret)) == null ||
			!getFunctionContaining(toAddr(ret)).getEntryPoint().equals(toAddr(caller))) {
			throw new AssertionError("window of " + toAddr(at) + ": last " + last + " return in " + getFunctionContaining(toAddr(ret)));
		}
		if (callee != null) {
			boolean found = false;
			for (Reference r : b.getReferencesFrom()) found |= r.getReferenceType().isCall() && r.getToAddress().equals(toAddr(callee));
			if (!found) throw new AssertionError("no call reference to " + toAddr(callee) + " from " + describe(b));
		}
	}

	private static String describe(Instruction i) {
		if (i == null) return "null";
		StringBuilder refs = new StringBuilder();
		for (Reference r : i.getReferencesFrom()) refs.append(' ').append(r.getReferenceType()).append(':').append(r.getToAddress());
		return i + " flow=" + i.getFlowType() + " override=" + i.getFlowOverride() + " fallthrough=" +
			i.getFallThrough() + " depth=" + i.getDelaySlotDepth() + " refs=" + refs;
	}
}
