// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check jumps landing in sequence in a tests/fixtures/in-sequence-jump.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class C6000InSequenceJumpTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1040L, 0x1080L, 0x10e0L, 0x1120L, 0x1160L, 0x11a0L, 0x11e0L, 0x1220L, 0x123cL };
	private static final String[] NAMES = { "seqone", "seqnest", "seqpair", "seqpredok", "seqearly", "seqpend", "seqpredw", "seqfork", "seqtail", "seqtailentry" };
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
			// As analysis leaves a jump onto a seeded entry: a tail call.
			getInstructionAt(toAddr(0x1220L)).setFlowOverride(ghidra.program.model.listing.FlowOverride.CALL_RETURN);
			return;
		}
		// In-sequence jumps transfer nowhere; the code they seemed to skip is lifted.
		for (long at : new long[] { 0x1000L, 0x1040L, 0x104cL, 0x1054L, 0x1094L, 0x10f0L, 0x11ecL, 0x1220L }) inert(at);
		// Known-bads: the target is past the landing, a real jump lands first, the predicate changed.
		for (long at : new long[] { 0x1120L, 0x116cL, 0x11b0L }) {
			Instruction i = getInstructionAt(toAddr(at));
			var inert = currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_inert"), toAddr(at), false);
			// Inside a window no native recovery lifts, it may stay undecoded; it must never be inert.
			if ((inert != null && inert.signum() != 0) || (i != null && !i.getFlowType().isJump())) throw new AssertionError("known-bad jump lost its transfer at " + toAddr(at) + ": " + i);
			checks++;
		}
		returns(0x1000L, "0x7f");
		returns(0x1040L, "0x3ff");
		returns(0x1080L, "0x7f");   // the register jump to out1 is native register-branch flow, not this check
		returns(0x10e0L, "0xff", "0x101");
		returns(0x1120L, "0x7f");
		// The complementary pair: the return owns the window, the jump is its not-taken fall-through.
		Instruction fork = getInstructionAt(toAddr(0x11e8L));
		if (fork == null || fork.getPrototype().getDelaySlotByteCount() <= 4 || !toAddr(0x1208L).equals(fork.getFallThrough()))
			throw new AssertionError("seqfork return at 0x11e8: " + fork + (fork == null ? "" : " delay bytes " + fork.getPrototype().getDelaySlotByteCount() + " fall-through " + fork.getFallThrough()));
		checks++;
		returns(0x11e0L, "0x3f", "0x7f");
		returns(0x1220L, "0x7f");
		println("C6000_IN_SEQUENCE_JUMP_OK checks=" + checks);
	}

	private void inert(long at) {
		Instruction i = getInstructionAt(toAddr(at));
		if (i == null || i.getFlowType().isJump() || i.getFlowType().isTerminal() || i.getPrototype().getDelaySlotByteCount() != 0 ||
			i.getReferencesFrom().length != 0 && java.util.Arrays.stream(i.getReferencesFrom()).anyMatch(r -> r.getReferenceType().isFlow()))
			throw new AssertionError("in-sequence jump still transfers at " + toAddr(at) + ": " + i + (i == null ? "" : " " + i.getFlowType()));
		checks++;
	}

	private void returns(long entry, String... constants) throws Exception {
		Function f = getFunctionAt(toAddr(entry));
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null)
				throw new AssertionError("decompile failed: " + (result == null ? "null" : result.getErrorMessage()));
			String c = result.getDecompiledFunction().getC();
			for (String k : constants) if (!c.matches("(?s).*\\b" + k + "\\b.*")) throw new AssertionError(f.getName() + " does not return " + k + ":\n" + c);
			checks++;
		}
		finally {
			decompiler.dispose();
		}
	}
}
