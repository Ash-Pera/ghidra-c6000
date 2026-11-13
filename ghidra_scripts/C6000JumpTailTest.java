// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check calls whose link a jump's target code sets, in a tests/fixtures/jump-tail.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

import java.math.BigInteger;

public class C6000JumpTailTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1160L, 0x1000L, 0x1060L, 0x10c0L, 0x1120L };
	private static final String[] NAMES = { "callee", "jtail", "jtailent", "jtaillink", "jtailfall" };
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
		// The issuing call is inert; the tail's last instruction carries it.
		inert(0x1010L);
		carries(0x1030L, 0x1160L);
		returns(0x1000L, "callee(param_2);");
		// Known-bads: the call keeps its transfer and no tail carries it.
		for (long[] k : new long[][] { { 0x107cL, 0x109cL }, { 0x10d0L, 0x10f0L }, { 0x1130L, 0x1144L } }) keeps(k[0], k[1]);
		println("C6000_JUMP_TAIL_OK checks=" + checks);
	}

	private boolean flagged(long at, String field) {
		BigInteger v = currentProgram.getProgramContext().getValue(currentProgram.getRegister(field), toAddr(at), false);
		return v != null && v.signum() != 0;
	}

	private void inert(long at) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || !flagged(at, "c_inert") || b.getFlowType().isJump() || b.getFlowType().isCall()) {
			throw new AssertionError("call at " + toAddr(at) + " not inert: " + (b == null ? "null" : b + " " + b.getFlowType()));
		}
		checks++;
	}

	private void carries(long at, long callee) {
		Instruction c = getInstructionAt(toAddr(at));
		boolean ref = false;
		if (c != null) for (Reference r : c.getReferencesFrom())
			ref |= r.getReferenceType() == RefType.CALL_OVERRIDE_UNCONDITIONAL && r.getToAddress().equals(toAddr(callee));
		if (c == null || !flagged(at, "c_carry") || !c.getFlowType().isCall() || !ref) {
			throw new AssertionError("tail at " + toAddr(at) + " carries no call: " + (c == null ? "null" : c + " " + c.getFlowType()));
		}
		checks++;
	}

	private void keeps(long call, long last) {
		if (flagged(call, "c_inert") || flagged(last, "c_carry")) {
			throw new AssertionError("known-bad call at " + toAddr(call) + " carried at " + toAddr(last));
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
			println("C6000_JUMP_TAIL_C " + c.replace('\n', ' '));
			checks++;
		}
		finally {
			decompiler.dispose();
		}
	}
}
