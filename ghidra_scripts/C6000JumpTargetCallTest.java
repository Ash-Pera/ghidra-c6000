// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check calls carried into their jump's target in a tests/fixtures/jump-target-call.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class C6000JumpTargetCallTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1020L, 0x1040L, 0x10a0L, 0x1100L, 0x1180L, 0x11e0L, 0x1240L, 0x12a0L };
	private static final String[] NAMES = { "h", "g", "tcdir", "tcreg", "tcarm", "tcbusy", "tcindep", "tclink", "tcfall" };
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
		// {call, carrier, landing, callee or 0 for a register call}
		for (long[] k : new long[][] { { 0x105cL, 0x1074L, 0x1078L, 0x1000L }, { 0x10c0L, 0x10d8L, 0x10dcL, 0L },
				{ 0x1130L, 0x114cL, 0x1150L, 0L }, { 0x1194L, 0x11b8L, 0x11bcL, 0x1000L } }) {
			Instruction call = getInstructionAt(toAddr(k[0])), carrier = getInstructionAt(toAddr(k[1]));
			if (call == null || call.getFlowType().isCall() || call.getFlowType().isJump() || call.getPrototype().getDelaySlotByteCount() != 0)
				throw new AssertionError("call still transfers at " + toAddr(k[0]) + ": " + call + (call == null ? "" : " " + call.getFlowType()));
			if (carrier == null || !carrier.getFlowType().isCall() || !toAddr(k[2]).equals(carrier.getFallThrough()) ||
					k[3] != 0 && (carrier.getFlows().length != 1 || !carrier.getFlows()[0].equals(toAddr(k[3]))))
				throw new AssertionError("carrier at " + toAddr(k[1]) + ": " + carrier + (carrier == null ? "" : " " + carrier.getFlowType() + " fall-through " + carrier.getFallThrough()));
			checks += 2;
		}
		// The call on the jump's taken path, the straight-line arm on the other.
		has(0x1040L, "\\bh\\(", "\\+ 7\\b");
		has(0x10a0L, "\\bh\\)?\\(", "\\+ 7\\b");
		has(0x1100L, "\\bh\\)?\\(", "\\bg\\(", "\\+ 0x10\\b");
		has(0x1180L, "\\bh\\(", "\\+ 7\\b", "\\+ 2\\b");
		// Known-bads: the call keeps its transfer, the target's last NOP does not call.
		for (long[] k : new long[][] { { 0x1200L, 0x1218L }, { 0x125cL, 0x1274L }, { 0x12bcL, 0x12c4L } }) {
			Instruction b = getInstructionAt(toAddr(k[0])), last = getInstructionAt(toAddr(k[1]));
			if (b != null && !(b.getFlowType().isCall() || b.getFlowType().isJump()) || last != null && last.getFlowType().isCall())
				throw new AssertionError("known-bad at " + toAddr(k[0]) + ": " + b + " / " + last);
			checks++;
		}
		println("C6000_JUMP_TARGET_CALL_OK checks=" + checks);
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
