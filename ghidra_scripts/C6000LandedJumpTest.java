// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check jumps that land where another jump's target code runs to, in a tests/fixtures/landed-jump.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

import java.math.BigInteger;

public class C6000LandedJumpTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1040L, 0x1080L, 0x10c0L, 0x1100L, 0x1140L };
	private static final String[] NAMES = { "landall", "landpred", "landuncond", "landshort", "landother",
		"landentered" };
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
		// The inner jump is inert and the outer window holds the load.
		inert(0x100cL);
		window(0x1000L, 12);
		returns(0x1000L, new String[] { "*(int *)(param_1 & 0xfffffffc) + 3" }, "in_A2");
		inert(0x1054L);
		window(0x1048L, 12);
		returns(0x1040L, new String[] { "*(int *)(param_2 & 0xfffffffc) + 3", "7" }, "in_A2");
		inert(0x1094L);
		window(0x1088L, 12);
		returns(0x1080L, new String[] { "*(int *)(param_2 & 0xfffffffc) + 3" }, "in_A2");
		// Known-bads: the inner jump keeps its target.
		for (long at : new long[] { 0x10ccL, 0x1118L, 0x1178L }) keeps(at);
		println("C6000_LANDED_JUMP_OK checks=" + checks);
	}

	private boolean flagged(long at) {
		BigInteger v = currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_inert"), toAddr(at), false);
		return v != null && v.signum() != 0;
	}

	private void inert(long at) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || !flagged(at) || b.getFlowType().isJump() || b.getFlows().length != 0) {
			throw new AssertionError("landed jump at " + toAddr(at) + " not inert: " + (b == null ? "null" : b + " " + b.getFlowType()));
		}
		checks++;
	}

	private void keeps(long at) {
		if (flagged(at)) throw new AssertionError("known-bad jump at " + toAddr(at) + " made inert");
		Instruction b = getInstructionAt(toAddr(at));
		if (b != null && !b.getFlowType().isJump()) throw new AssertionError("known-bad jump at " + toAddr(at) + ": " + b.getFlowType());
		checks++;
	}

	private void window(long at, int bytes) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || b.getPrototype().getDelaySlotByteCount() != bytes) {
			throw new AssertionError("window at " + toAddr(at) + ": " + (b == null ? "null" : b + " bytes " + b.getPrototype().getDelaySlotByteCount()));
		}
		checks++;
	}

	private void returns(long entry, String[] expected, String absent) throws Exception {
		Function f = getFunctionAt(toAddr(entry));
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null) {
				throw new AssertionError("decompile failed: " + (result == null ? "null" : result.getErrorMessage()));
			}
			String c = result.getDecompiledFunction().getC();
			for (String e : expected) if (!c.contains(e)) throw new AssertionError(f.getName() + " lacks " + e + ":\n" + c);
			if (c.contains(absent)) throw new AssertionError(f.getName() + " holds " + absent + ":\n" + c);
			checks++;
		}
		finally {
			decompiler.dispose();
		}
	}
}
