// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check a B call with 30 instructions in its window in a tests/fixtures/wide-call-window.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;

public class C6000WideCallWindowTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			disassemble(toAddr(0x1000L));
			createFunction(toAddr(0x1000L), "wide");
			disassemble(toAddr(0x10a0L));
			createFunction(toAddr(0x10a0L), "callee");
			return;
		}
		// A packet holds up to eight instructions, so five delay cycles can hold 40 (SPRUFE8B 3.5).
		Instruction b = getInstructionAt(toAddr(0x1004L));
		Instruction last = getInstructionAt(toAddr(0x107cL));
		if (b == null || !b.getFlowType().isCall() || b.getFlowType().isTerminal() ||
			!toAddr(0x1080L).equals(b.getFallThrough()) || last == null || !last.isInDelaySlot()) {
			throw new AssertionError("call at 0x1004: " + describe(b) + "; last slot " + last);
		}
		// Its return point is code of the caller, and the return there is classified.
		Instruction ret = getInstructionAt(toAddr(0x108cL));
		if (ret == null || !ret.getFlowType().isTerminal() || getFunctionContaining(toAddr(0x108cL)) == null ||
			!getFunctionContaining(toAddr(0x108cL)).getEntryPoint().equals(toAddr(0x1000L))) {
			throw new AssertionError("return at 0x108c: " + describe(ret));
		}
		println("C6000_WIDE_CALL_WINDOW_OK checks=2");
	}

	private static String describe(Instruction i) {
		return i == null ? "null" : i + " flow=" + i.getFlowType() + " override=" + i.getFlowOverride() +
			" fallthrough=" + i.getFallThrough() + " depth=" + i.getDelaySlotDepth();
	}
}
