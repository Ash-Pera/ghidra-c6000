// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check a jump preempted by a link-copy return in a tests/fixtures/preempted-link-copy.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class C6000PreemptedLinkCopyTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1040L };
	private static final String[] NAMES = { "copyret", "copyother" };
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
		// The jump continues into its window; the copy return's window ends where the jump lands.
		Instruction jump = getInstructionAt(toAddr(0x1008L));
		Address override = null;
		for (Reference r : jump.getReferencesFrom()) {
			if (r.getReferenceType() == RefType.JUMP_OVERRIDE_UNCONDITIONAL && r.isPrimary()) override = r.getToAddress();
			else if (r.getReferenceType().isFlow() && r.getToAddress().equals(toAddr(0x1034L)))
				throw new AssertionError("jump still flows to pad1: " + java.util.Arrays.toString(jump.getReferencesFrom()));
		}
		if (!toAddr(0x100cL).equals(override)) throw new AssertionError("jump overridden to " + override);
		checks++;
		window(0x1010L, 4);
		window(0x1028L, 3);
		String c = decompile(0x1000L);
		if (!c.contains("0x111") || !c.contains("0x333")) throw new AssertionError("copyret:\n" + c);
		checks++;
		// Known-bad: B A0 copies B4, so the jump keeps its target.
		Instruction other = getInstructionAt(toAddr(0x1048L));
		for (Reference r : other.getReferencesFrom())
			if (r.getReferenceType().isOverride()) throw new AssertionError("copyother's jump overridden");
		if (other.getFlows().length != 1 || !other.getFlows()[0].equals(toAddr(0x1074L)))
			throw new AssertionError("copyother's jump lost its target");
		checks++;
		println("C6000_PREEMPTED_LINK_COPY_OK checks=" + checks);
	}

	private void window(long at, int depth) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || b.getDelaySlotDepth() != depth || b.getFlowOverride() != FlowOverride.RETURN)
			throw new AssertionError("window at " + toAddr(at) + ": " + (b == null ? "null" : b + " depth " +
				b.getDelaySlotDepth() + " override " + b.getFlowOverride()));
		checks++;
	}

	private String decompile(long entry) throws Exception {
		Function f = getFunctionAt(toAddr(entry));
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null)
				throw new AssertionError("decompile failed: " + (result == null ? "null" : result.getErrorMessage()));
			return result.getDecompiledFunction().getC();
		}
		finally {
			decompiler.dispose();
		}
	}
}
