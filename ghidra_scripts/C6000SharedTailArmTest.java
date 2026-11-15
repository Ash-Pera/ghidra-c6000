// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check a shared call tail whose jump holds a call arm, in a tests/fixtures/shared-tail-arm.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class C6000SharedTailArmTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x10c0L, 0x10e0L, 0x1100L, 0x1000L, 0x1060L };
	private static final String[] NAMES = { "callee", "callee2", "callee3", "tailarm", "armother" };
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
		// The jump lifts its whole window: both calls in it are inert.
		Instruction jump = getInstructionAt(toAddr(0x1028L)), tailCall = getInstructionAt(toAddr(0x1030L)),
			arm = getInstructionAt(toAddr(0x1038L)), tail = getInstructionAt(toAddr(0x101cL)), last = getInstructionAt(toAddr(0x104cL));
		if (jump == null || jump.getPrototype().getDelaySlotByteCount() != 32)
			throw new AssertionError("jump: " + jump + (jump == null ? "" : " delay bytes " + jump.getPrototype().getDelaySlotByteCount()));
		checks++;
		for (Instruction i : new Instruction[] { tailCall, arm })
			if (i == null || i.getFlowType().isCall() || i.getFlowType().isJump() || i.getPrototype().getDelaySlotByteCount() != 0)
				throw new AssertionError("call in the jump's window still transfers: " + i);
		checks++;
		// The tail carries callee; the call arm's last slot carries callee2 and resumes at exit1.
		carrier(tail, 0x10c0L, 0x1020L);
		carrier(last, 0x10e0L, 0x1050L);
		// The loop's call takes B4 = 7 from the jump's slots (callee(a, b) as a header would declare it).
		var callee = getFunctionAt(toAddr(0x10c0L));
		var it = ghidra.program.model.data.IntegerDataType.dataType;
		callee.updateFunction(null, new ghidra.program.model.listing.ReturnParameterImpl(it, currentProgram),
			java.util.List.of(new ghidra.program.model.listing.ParameterImpl("a", it, currentProgram),
				new ghidra.program.model.listing.ParameterImpl("b", it, currentProgram)),
			Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, ghidra.program.model.symbol.SourceType.USER_DEFINED);
		String c = decompile(0x1000L);
		int loop = Math.min(c.indexOf("while") < 0 ? c.length() : c.indexOf("while"), c.indexOf("do {") < 0 ? c.length() : c.indexOf("do {"));
		String body = loop == c.length() ? "" : c.substring(loop);
		if (!body.matches("(?s).*callee\\([^;]*,7\\).*") || !c.contains("callee2("))
			throw new AssertionError("tailarm:\n" + c);
		checks++;
		// Known-bad: the call to callee3 is no shared tail, so the call arm keeps its transfer.
		Instruction other = getInstructionAt(toAddr(0x1098L)), otherLast = getInstructionAt(toAddr(0x10acL));
		if (other == null || !(other.getFlowType().isCall() || other.getFlowType().isJump()) || otherLast == null || otherLast.getFlowType().isCall())
			throw new AssertionError("known-bad armother: " + other + " / " + otherLast);
		checks++;
		println("C6000_SHARED_TAIL_ARM_OK checks=" + checks);
	}

	private void carrier(Instruction i, long callee, long resume) {
		if (i == null || !i.getFlowType().isCall() || i.getFlows().length != 1 || !i.getFlows()[0].equals(toAddr(callee)) ||
				!toAddr(resume).equals(i.getFallThrough()))
			throw new AssertionError("carrier: " + i + (i == null ? "" : " " + i.getFlowType() + " fall " + i.getFallThrough()));
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
			return result.getDecompiledFunction().getC().replace(" ", "");
		}
		finally {
			decompiler.dispose();
		}
	}
}
