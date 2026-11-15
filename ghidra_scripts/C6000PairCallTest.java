// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check a register call paired with a complementary jump, in a tests/fixtures/pair-call.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;

public class C6000PairCallTest extends GhidraScript {
	private int checks;

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			long[] entries = { 0x10c0L, 0x1000L, 0x1060L };
			String[] names = { "callee", "paircall", "pairentry" };
			for (int i = 0; i < entries.length; i++) {
				disassemble(toAddr(entries[i]));
				createFunction(toAddr(entries[i]), names[i]);
			}
			return;
		}
		// The jump is inert; the call lays its window, falls through to other1 and returns to ret1.
		Instruction jump = getInstructionAt(toAddr(0x1018L)), call = getInstructionAt(toAddr(0x1014L));
		if (jump == null || jump.getFlowType().isJump() || jump.getFlowType().isCall())
			throw new AssertionError("paired jump still transfers: " + jump);
		checks++;
		if (call == null || !call.getFlowType().isCall() || call.getPrototype().getDelaySlotByteCount() != 28 ||
				!toAddr(0x1038L).equals(call.getFallThrough()) || java.util.Arrays.stream(call.getReferencesFrom()).noneMatch(r ->
					r.getReferenceType() == RefType.CALLOTHER_OVERRIDE_JUMP && r.isPrimary() && r.getToAddress().equals(toAddr(0x1034L))))
			throw new AssertionError("call: " + call + (call == null ? "" : " delay bytes " + call.getPrototype().getDelaySlotByteCount() +
				" fall " + call.getFallThrough() + " refs " + java.util.Arrays.toString(call.getReferencesFrom())));
		checks++;
		var body = ghidra.app.cmd.function.CreateFunctionCmd.getFunctionBody(currentProgram, toAddr(0x1000L), monitor);
		if (!body.contains(toAddr(0x1000L), toAddr(0x1043L))) throw new AssertionError("paircall body from flow " + body);
		checks++;
		var callee = getFunctionAt(toAddr(0x10c0L));
		var it = ghidra.program.model.data.IntegerDataType.dataType;
		callee.updateFunction(null, new ghidra.program.model.listing.ReturnParameterImpl(it, currentProgram),
			java.util.List.of(new ghidra.program.model.listing.ParameterImpl("a", it, currentProgram),
				new ghidra.program.model.listing.ParameterImpl("b", it, currentProgram)),
			Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, ghidra.program.model.symbol.SourceType.USER_DEFINED);
		String c = decompile(0x1000L);
		if (!c.contains("callee(5,9)") || !c.contains("7") || c.contains("c6000_pair_return"))
			throw new AssertionError("paircall:\n" + c);
		checks++;
		// Known-bad: a jump enters pairentry's window, so its pair keeps both transfers.
		Instruction other = getInstructionAt(toAddr(0x107cL));
		if (other == null || !other.getFlowType().isJump()) throw new AssertionError("known-bad pairentry: " + other);
		checks++;
		println("C6000_PAIR_CALL_OK checks=" + checks);
	}

	private String decompile(long entry) throws Exception {
		Function f = getFunctionAt(toAddr(entry));
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null)
				throw new AssertionError("decompile failed: " + (result == null ? "null" : result.getErrorMessage()));
			return result.getDecompiledFunction().getC().replace(" ", "");
		}
		finally {
			decompiler.dispose();
		}
	}
}
