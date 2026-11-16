// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check calls carried into their jump's target in a tests/fixtures/jump-target-call.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000JumpTargetCallTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1020L, 0x1040L, 0x10a0L, 0x1100L, 0x1180L, 0x11e0L, 0x1240L, 0x12a0L, 0x12e0L, 0x1340L, 0x13a0L, 0x13c0L, 0x1420L };
	private static final String[] NAMES = { "h", "g", "tcdir", "tcreg", "tcarm", "tcbusy", "tcindep", "tclink", "tcfall", "tcuncond", "tcentry", "tcenter", "tcearly", "tcboth" };
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
		// {call, carrier, landing, callee or 0 for a register call, entry, jump, window's last byte}
		for (long[] k : new long[][] { { 0x10c0L, 0x10d8L, 0x10dcL, 0L, 0x10a0L, 0x10acL, 0x10c3L }, { 0x1130L, 0x114cL, 0x1150L, 0L, 0x1100L, 0x1114L, 0x1133L },
				{ 0x1198L, 0x11bcL, 0x11c0L, 0L, 0x1180L, 0x118cL, 0x119fL } }) {
			Instruction call = getInstructionAt(toAddr(k[0])), carrier = getInstructionAt(toAddr(k[1]));
			if (call == null || call.getFlowType().isCall() || call.getFlowType().isJump() || call.getPrototype().getDelaySlotByteCount() != 0)
				throw new AssertionError("call still transfers at " + toAddr(k[0]) + ": " + call + (call == null ? "" : " " + call.getFlowType()));
			if (carrier == null || !carrier.getFlowType().isCall() || !toAddr(k[2]).equals(carrier.getFallThrough()) ||
					k[3] != 0 && (carrier.getFlows().length != 1 || !carrier.getFlows()[0].equals(toAddr(k[3]))))
				throw new AssertionError("carrier at " + toAddr(k[1]) + ": " + carrier + (carrier == null ? "" : " " + carrier.getFlowType() + " fall-through " + carrier.getFallThrough()));
			// The jump lifts its whole window; a body recomputed from flow keeps it.
			Instruction jump = getInstructionAt(toAddr(k[5]));
			var body = ghidra.app.cmd.function.CreateFunctionCmd.getFunctionBody(currentProgram, toAddr(k[4]));
			if (jump == null || !jump.getMaxAddress().add(jump.getPrototype().getDelaySlotByteCount()).equals(toAddr(k[6])) ||
					!body.contains(toAddr(k[5]), toAddr(k[6])) || !body.contains(toAddr(k[1])))
				throw new AssertionError("jump at " + toAddr(k[5]) + ": " + jump + (jump == null ? "" : " depth " + jump.getDelaySlotDepth()) + " flow body " + body);
			checks += 3;
		}
		// Direct calls {call, carrier, landing, callee, entry, jump, window's last byte, jump's carrier}: the jump has no native window, its last slot jumps.
		for (long[] k : new long[][] { { 0x105cL, 0x1074L, 0x1078L, 0x1000L, 0x1040L, 0x104cL, 0x105fL, 0x105cL },
				{ 0x13d4L, 0x13f8L, 0x13fcL, 0x1000L, 0x13c0L, 0x13ccL, 0x13dbL, 0x13d8L },
				{ 0x1434L, 0x1468L, 0x146cL, 0x1000L, 0x1420L, 0x142cL, 0x1443L, 0x1440L } }) {
			Instruction call = getInstructionAt(toAddr(k[0])), carrier = getInstructionAt(toAddr(k[1]));
			Instruction jump = getInstructionAt(toAddr(k[5])), jc = getInstructionAt(toAddr(k[7]));
			if (call == null || call.getFlowType().isCall() || call.getPrototype().getDelaySlotByteCount() != 0 || k[0] != k[7] && call.getFlowType().isJump())
				throw new AssertionError("call still transfers at " + toAddr(k[0]) + ": " + call + (call == null ? "" : " " + call.getFlowType()));
			if (carrier == null || !carrier.getFlowType().isCall() || !toAddr(k[2]).equals(carrier.getFallThrough()) ||
					carrier.getFlows().length != 1 || !carrier.getFlows()[0].equals(toAddr(k[3])))
				throw new AssertionError("carrier at " + toAddr(k[1]) + ": " + carrier + (carrier == null ? "" : " " + carrier.getFlowType()));
			if (jump == null || jump.getFlowType().isJump() || jump.getPrototype().getDelaySlotByteCount() != 0)
				throw new AssertionError("jump still transfers at " + toAddr(k[5]) + ": " + jump + (jump == null ? "" : " " + jump.getFlowType()));
			if (jc == null || !jc.getFlowType().isJump() || !jc.getFlowType().isConditional() || jc.getFlows().length != 1 ||
					!jc.getMaxAddress().equals(toAddr(k[6])) || !jc.getMaxAddress().next().equals(jc.getFallThrough()))
				throw new AssertionError("jump's carrier at " + toAddr(k[7]) + ": " + jc + (jc == null ? "" : " " + jc.getFlowType() + " flows " + java.util.Arrays.toString(jc.getFlows())));
			// As fixupFunctionBody recomputes it: the whole window and the target, not the callee.
			var body = ghidra.app.cmd.function.CreateFunctionCmd.getFunctionBody(currentProgram, toAddr(k[4]), monitor);
			if (!body.contains(toAddr(k[5]), toAddr(k[6])) || !body.contains(jc.getFlows()[0], toAddr(k[1]).add(3)) || body.contains(toAddr(k[3])))
				throw new AssertionError("flow body of " + toAddr(k[4]) + ": " + body);
			checks += 4;
		}
		// tcboth's call arm: inert, its last slot past the jump's calls g.
		Instruction armCall = getInstructionAt(toAddr(0x1430L)), armLast = getInstructionAt(toAddr(0x1444L));
		if (armCall == null || armCall.getFlowType().isCall() || armCall.getFlowType().isJump() || armLast == null || !armLast.getFlowType().isCall() ||
				armLast.getFlows().length != 1 || !armLast.getFlows()[0].equals(toAddr(0x1020L)) || !toAddr(0x1448L).equals(armLast.getFallThrough()))
			throw new AssertionError("tcboth's arm: " + armCall + " / " + armLast);
		checks++;
		// The call on the jump's taken path, the straight-line arm on the other.
		has(0x1040L, "\\bh\\)?\\(", "\\+ 7\\b");
		has(0x10a0L, "\\bh\\)?\\(", "\\+ 7\\b");
		has(0x1100L, "\\bh\\)?\\(", "\\bg\\(", "\\+ 0x10\\b");
		has(0x1180L, "\\bh\\)?\\(", "\\+ 7\\b", "\\+ 2\\b");
		has(0x13c0L, "\\bh\\)?\\(", "\\+ 7\\b", "\\+ 2\\b");
		has(0x1420L, "\\bh\\)?\\(", "\\bg\\)?\\(", "\\+ 0x10\\b", "\\+ 2\\b");
		// Known-bads: the call keeps its transfer, the target's last NOP does not call.
		for (long[] k : new long[][] { { 0x1204L, 0x121cL }, { 0x1260L, 0x1278L }, { 0x12c0L, 0x12c8L }, { 0x1300L, 0x131cL }, { 0x1360L, 0x1378L } }) {
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
