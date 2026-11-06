// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Nested delay windows on a tests/fixtures/nested-window.py image: a same-target branch issued
// inside another branch's window gets the outer its full window (the inner is a sound slot goto);
// work after the inner, a call, or a differing target keep the window refused.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class C6000NestedWindowTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1024L, 0x1048L, 0x1068L, 0x1088L, 0x10a4L };
	private static final String[] NAMES = { "chain", "chain3", "nullinner", "tailwork", "callwin", "wcallee" };
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
		// Sound: the two same-target prologue branches recover the outer's full window.
		recovered(0x1000L, 0x100cL);           // inner B targets cdone, just like the outer
		recovered(0x1048L, 0x1054L);           // predicated inner, same target, A0 nullified, inert tail
		returns(0x1000L, "0x15");              // param + 10 + 10 + 1; native-only gives param + 1
		returns(0x1048L, "0xe");               // param + 12 + 2; native-only gives param + 2
		// Refused: no sound one-window form.
		refused(0x1024L);                      // chain3: work (ADD) after the inner branch
		refused(0x1068L);                      // tailwork: work after the inner branch
		refused(0x1088L);                      // callwin: a CALLP issues in the window
		println("C6000_NESTED_WINDOW_OK checks=" + checks);
	}

	/** The outer owns a recovered delay window and the inner branch is one of its slots. */
	private void recovered(long outer, long inner) {
		Instruction b = getInstructionAt(toAddr(outer));
		if (b == null || b.getDelaySlotDepth() == 0) {
			throw new AssertionError("outer at " + toAddr(outer) + " has no window: " + b);
		}
		Instruction in = getInstructionAt(toAddr(inner));
		if (in == null || !in.isInDelaySlot()) {
			throw new AssertionError("inner at " + toAddr(inner) + " is not a slot: " + in);
		}
		checks++;
	}

	private void refused(long outer) {
		Instruction b = getInstructionAt(toAddr(outer));
		if (b == null || b.getDelaySlotDepth() != 0) {
			throw new AssertionError("outer at " + toAddr(outer) + " wrongly got a window: " + b +
				" depth " + (b == null ? -1 : b.getDelaySlotDepth()));
		}
		checks++;
	}

	private void returns(long entry, String expected) throws Exception {
		Function f = getFunctionAt(toAddr(entry));
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null) {
				throw new AssertionError("decompile failed: " + (result == null ? "null" : result.getErrorMessage()));
			}
			String c = result.getDecompiledFunction().getC();
			if (!c.contains(expected)) throw new AssertionError(f.getName() + " lacks " + expected + ":\n" + c);
			checks++;
		}
		finally {
			decompiler.dispose();
		}
	}
}
