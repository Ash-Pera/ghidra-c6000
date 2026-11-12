// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check call tails shared by a jump in a tests/fixtures/shared-tail.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class C6000SharedTailTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x11e0L, 0x1200L, 0x1000L, 0x1060L, 0x10c0L, 0x1120L, 0x1180L };
	private static final String[] NAMES = { "callee", "callee2", "tailidle", "tailbusy", "tailpred", "tailother",
		"tailentry" };
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
		// The tail's last instruction carries the call; both branches that issued it no longer transfer.
		// The loop calls callee on every iteration (natively the loop's call was lost).
		loopCalls(0x1000L);
		loopCalls(0x1060L);
		carried(0x101cL, 0x1008L, 0x102cL, 0x1028L);
		carried(0x107cL, 0x106cL, 0x108cL, 0x1088L);
		// Known-bads: the first call keeps its own transfer and no tail instruction calls.
		for (long[] c : new long[][] { { 0x10e0L, 0x10d0L }, { 0x113cL, 0x112cL }, { 0x11a8L, 0x1198L } }) {
			Instruction tail = getInstructionAt(toAddr(c[0])), call = getInstructionAt(toAddr(c[1]));
			if (tail == null || tail.getFlowType().isCall() || call == null || !call.getFlowType().isCall())
				throw new AssertionError("known-bad tail at " + toAddr(c[0]) + ": " + tail + " / " + call);
			checks++;
		}
		println("C6000_SHARED_TAIL_OK checks=" + checks);
	}

	/** The tail instruction calls callee and falls through; the two issuing branches are inert; the jump has a window. */
	private void carried(long tail, long first, long second, long jump) {
		Instruction t = getInstructionAt(toAddr(tail)), a = getInstructionAt(toAddr(first)), b = getInstructionAt(toAddr(second)),
			j = getInstructionAt(toAddr(jump));
		if (t == null || !t.getFlowType().isCall() || t.getFlows().length != 1 || !t.getFlows()[0].equals(toAddr(0x11e0L)) ||
			!toAddr(tail + 4).equals(t.getFallThrough()))
			throw new AssertionError("tail at " + toAddr(tail) + ": " + t + (t == null ? "" : " " + t.getFlowType()));
		for (Instruction i : new Instruction[] { a, b })
			if (i == null || i.getFlowType().isCall() || i.getFlowType().isJump() || i.getPrototype().getDelaySlotByteCount() != 0)
				throw new AssertionError("issuing branch still transfers: " + i);
		if (j == null || j.getPrototype().getDelaySlotByteCount() == 0 || !java.util.Arrays.stream(j.getReferencesFrom()).anyMatch(r -> r.getReferenceType().isJump() && r.getToAddress().equals(toAddr(tail))))
			throw new AssertionError("jump at " + toAddr(jump) + ": " + j + (j == null ? "" : " delay bytes " + j.getPrototype().getDelaySlotByteCount() + " refs " + java.util.Arrays.toString(j.getReferencesFrom())));
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
