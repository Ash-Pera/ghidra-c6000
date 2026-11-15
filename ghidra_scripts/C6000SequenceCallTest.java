// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check a register call with an in-sequence jump in its packet, in a tests/fixtures/sequence-call.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class C6000SequenceCallTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1160L, 0x1000L, 0x1040L, 0x10a0L, 0x10e0L, 0x1120L };
	private static final String[] NAMES = { "callee", "seqcall", "seqreg", "seqsame", "seqmix", "sequnc" };
	private static final long[] FORCED = { 0x1068L, 0x10bcL, 0x1104L, 0x1144L };
	private static final long[] CALLS = { 0x1058L, 0x10acL, 0x10f4L, 0x1134L };
	private int checks;

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			// Known-bads: one more branch in the call's window decoded inert.
			for (long at : FORCED) currentProgram.getProgramContext().setValue(currentProgram.getRegister("c_inert"),
				toAddr(at), toAddr(at), java.math.BigInteger.ONE);
			for (int i = 0; i < ENTRIES.length; i++) {
				disassemble(toAddr(ENTRIES[i]));
				createFunction(toAddr(ENTRIES[i]), NAMES[i]);
			}
			return;
		}
		// The jump is inert; the call lays its whole window over it and resumes at ret1.
		Instruction jump = getInstructionAt(toAddr(0x1018L)), call = getInstructionAt(toAddr(0x1014L));
		if (jump == null || jump.getFlowType().isJump() || jump.getFlowType().isCall())
			throw new AssertionError("in-sequence jump still transfers: " + jump);
		checks++;
		if (call == null || !call.getFlowType().isCall() || call.getPrototype().getDelaySlotByteCount() != 24 ||
				call.getDelaySlotDepth() != 6 || !toAddr(0x1030L).equals(call.getFallThrough()))
			throw new AssertionError("call: " + call + (call == null ? "" : " delay bytes " + call.getPrototype().getDelaySlotByteCount() +
				" depth " + call.getDelaySlotDepth() + " fall " + call.getFallThrough()));
		checks++;
		var body = ghidra.app.cmd.function.CreateFunctionCmd.getFunctionBody(currentProgram, toAddr(0x1000L), monitor);
		if (!body.contains(toAddr(0x1000L), toAddr(0x103bL))) throw new AssertionError("seqcall body from flow " + body);
		checks++;
		// The call's arguments come from its slots: callee(5, 9).
		var callee = getFunctionAt(toAddr(0x1160L));
		var it = ghidra.program.model.data.IntegerDataType.dataType;
		callee.updateFunction(null, new ghidra.program.model.listing.ReturnParameterImpl(it, currentProgram),
			java.util.List.of(new ghidra.program.model.listing.ParameterImpl("a", it, currentProgram),
				new ghidra.program.model.listing.ParameterImpl("b", it, currentProgram)),
			Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, ghidra.program.model.symbol.SourceType.USER_DEFINED);
		String c = decompile(0x1000L);
		if (!c.contains("callee(5,9)")) throw new AssertionError("seqcall:\n" + c);
		checks++;
		// Known-bads: the call's window never reaches the forced inert branch.
		for (int i = 0; i < CALLS.length; i++) {
			Instruction k = getInstructionAt(toAddr(CALLS[i]));
			if (k == null || k.getMaxAddress().add(k.getPrototype().getDelaySlotByteCount()).compareTo(toAddr(FORCED[i])) >= 0)
				throw new AssertionError("known-bad " + NAMES[i + 2] + ": call " + k + (k == null ? "" : " delay bytes " + k.getPrototype().getDelaySlotByteCount()));
			checks++;
		}
		println("C6000_SEQUENCE_CALL_OK checks=" + checks);
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
