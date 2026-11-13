// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check a jump with a call arm in its window in a tests/fixtures/call-arm.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class C6000CallArmTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1180L, 0x1000L, 0x1060L, 0x10c0L, 0x1120L };
	private static final String[] NAMES = { "callee", "armcall", "armsame", "armwrite", "armentry" };
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
		// Both arms: 8 from the jump's slots when p, else callee(0).
		String c = decompile(0x1000L);
		if (!c.contains("return 8;") || !c.contains("callee("))
			throw new AssertionError("armcall:\n" + c);
		checks++;
		// The jump lifts its whole window over the inert call; the call's last slot carries the call.
		Instruction jump = getInstructionAt(toAddr(0x1014L)), call = getInstructionAt(toAddr(0x101cL)),
			carrier = getInstructionAt(toAddr(0x102cL));
		if (jump == null || jump.getPrototype().getDelaySlotByteCount() != 20 || !java.util.Arrays.stream(jump.getReferencesFrom())
				.anyMatch(r -> r.getReferenceType().isJump() && r.getToAddress().equals(toAddr(0x103cL))))
			throw new AssertionError("jump: " + jump + (jump == null ? "" : " delay bytes " + jump.getPrototype().getDelaySlotByteCount()));
		if (call == null || call.getFlowType().isCall() || call.getFlowType().isJump() || call.getPrototype().getDelaySlotByteCount() != 0)
			throw new AssertionError("call arm still transfers: " + call);
		if (carrier == null || !carrier.getFlowType().isCall() || carrier.getFlows().length != 1 ||
				!carrier.getFlows()[0].equals(toAddr(0x1180L)) || !toAddr(0x1030L).equals(carrier.getFallThrough()))
			throw new AssertionError("carrier: " + carrier + (carrier == null ? "" : " " + carrier.getFlowType()));
		checks += 3;
		// Ghidra counts the jump's five slots past the inert call, so a body recomputed from flow keeps them.
		Function f = getFunctionAt(toAddr(0x1000L));
		var body = ghidra.app.cmd.function.CreateFunctionCmd.getFunctionBody(currentProgram, toAddr(0x1000L));
		if (jump.getDelaySlotDepth() != 5 || !body.contains(toAddr(0x101cL), toAddr(0x102bL)) || !f.getBody().contains(toAddr(0x101cL), toAddr(0x102bL)))
			throw new AssertionError("slots outside armcall: depth " + jump.getDelaySlotDepth() + " flow body " + body + " body " + f.getBody());
		checks++;
		// Known-bads: the call keeps its transfer and its last slot does not call.
		for (long[] k : new long[][] { { 0x107cL, 0x108cL }, { 0x10dcL, 0x10ecL }, { 0x1140L, 0x1150L } }) {
			Instruction b = getInstructionAt(toAddr(k[0])), last = getInstructionAt(toAddr(k[1]));
			if (b == null || !(b.getFlowType().isCall() || b.getFlowType().isJump()) || last == null || last.getFlowType().isCall())
				throw new AssertionError("known-bad at " + toAddr(k[0]) + ": " + b + " / " + last);
			checks++;
		}
		println("C6000_CALL_ARM_OK checks=" + checks);
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
