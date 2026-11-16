// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check jumps to a function whose link is a loop head in a tests/fixtures/link-jump.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class C6000LinkJumpTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1020L, 0x1040L, 0x1080L, 0x10c0L, 0x1100L, 0x1140L, 0x1180L };
	private static final String[] NAMES = { "h", "g", "ljloop", "ljonly", "ljwrite", "ljbusy", "ljpred", "ljclob" };
	private int checks;

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1040L));
			C6000PacketContext.prime(currentProgram, monitor);
			for (int i = 0; i < ENTRIES.length; i++) {
				disassemble(toAddr(ENTRIES[i]));
				createFunction(toAddr(ENTRIES[i]), NAMES[i]);
			}
			return;
		}
		// {jump, carrier}: the jump stops transferring and its last slot calls g.
		for (long[] k : new long[][] { { 0x1064L, 0x106cL }, { 0x1094L, 0x109cL } }) {
			Instruction jump = getInstructionAt(toAddr(k[0])), carrier = getInstructionAt(toAddr(k[1]));
			if (jump == null || jump.getFlowType().isJump() || jump.getFlowType().isCall() || jump.getPrototype().getDelaySlotByteCount() != 0)
				throw new AssertionError("jump still transfers at " + toAddr(k[0]) + ": " + jump + (jump == null ? "" : " " + jump.getFlowType()));
			if (carrier == null || !carries(carrier) || !callsG(carrier))
				throw new AssertionError("carrier at " + toAddr(k[1]) + ": " + carrier);
			checks += 2;
		}
		// The loop call returns to the loop head; the other path tail-calls.
		has(0x1040L, "\\bh\\(", "\\bg\\(", "while|do \\{|for \\(|goto", "== 0x1060\\b");
		has(0x1080L, "\\bg\\(", "while|do \\{|for \\(|goto", "== 0x1090\\b");
		// Known-bads: the jump keeps its transfer, its last slot carries nothing.
		for (long[] k : new long[][] { { 0x10d4L, 0x10e4L }, { 0x1114L, 0x111cL }, { 0x1150L, 0x1158L }, { 0x1198L, 0x119cL } }) {
			Instruction b = getInstructionAt(toAddr(k[0])), last = getInstructionAt(toAddr(k[1]));
			if (b == null || !(b.getFlowType().isCall() || b.getFlowType().isJump()) || last != null && carries(last))
				throw new AssertionError("known-bad at " + toAddr(k[0]) + ": " + b + " / " + last);
			checks++;
		}
		println("C6000_LINK_JUMP_OK checks=" + checks);
	}

	private boolean carries(Instruction insn) {
		var value = currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_carry"), insn.getAddress(), false);
		return value != null && value.signum() != 0;
	}

	private boolean callsG(Instruction insn) {
		for (Reference r : insn.getReferencesFrom())
			if (r.getReferenceType().isCall() && r.isPrimary() && r.getToAddress().equals(toAddr(0x1020L))) return true;
		return false;
	}

	private void has(long entry, String... patterns) throws Exception {
		Function f = getFunctionAt(toAddr(entry));
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null)
				throw new AssertionError("decompile failed: " + (result == null ? "null" : result.getErrorMessage()));
			String c = result.getDecompiledFunction().getC();
			for (String p : patterns) if (!java.util.regex.Pattern.compile(p).matcher(c).find())
				throw new AssertionError(f.getName() + " lacks " + p + ":\n" + c);
			checks++;
		}
		finally {
			decompiler.dispose();
		}
	}
}
