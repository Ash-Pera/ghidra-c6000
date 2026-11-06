// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Delay-window recovery over a call a flow repair disassembled outside any
// function body, in a tests/fixtures/merge-call-window.py image.
// Run as a postScript with -noanalysis (verify.py: analysis=False).

import c6000.C6000DelaySlots;
import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

public class C6000MergeCallWindowTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		// Run with -noanalysis, as a flow repair is: auto-analysis would decode
		// this small image whole and recover the window before the repair runs.
		C6000PacketContext.prime(currentProgram, monitor);

		Address issue = toAddr(0x1044L);   // LDW .. || B callee : the delayed call
		Address last = toAddr(0x1050L);    // ADD 0,B5,A4 : the last delay slot (the MV into A4)

		// A flow repair decodes the packet with no function over it: exactly the
		// state the single -noanalysis recovery pass runs in.
		disassemble(toAddr(0x1040L));
		if (getFunctionContaining(issue) != null || getFunctionContaining(toAddr(0x1040L)) != null) {
			throw new AssertionError("fixture precondition: the packet must be unowned, got "
				+ getFunctionContaining(issue));
		}
		Instruction call = getInstructionAt(issue);
		if (call == null || !call.getMnemonicString().equals("B.S1")) {
			throw new AssertionError("fixture shape changed: issue is " + call);
		}
		if (call.getPrototype().getDelaySlotByteCount() != 0) {
			throw new AssertionError("fixture precondition: the window is already native, recovery not exercised: " + call);
		}

		C6000DelaySlots.recover(currentProgram, monitor, new MessageLog());

		call = getInstructionAt(issue);
		int window = call == null ? -1 : call.getPrototype().getDelaySlotByteCount();
		if (window != 12) {
			throw new AssertionError("delay window not recovered over an unowned flow-repaired call: "
				+ "B.S1 delaySlotByteCount=" + window + " (expected 12), call=" + call);
		}
		Instruction mv = getInstructionAt(last);
		if (mv == null || !mv.isInDelaySlot()) {
			throw new AssertionError("the last-slot move is not in the call's delay window: " + mv);
		}
		Register a4 = currentProgram.getRegister("A4");
		boolean writesA4 = false;
		for (Object result : mv.getResultObjects()) {
			if (result instanceof Register r && r.contains(a4)) writesA4 = true;
		}
		if (!writesA4) {
			throw new AssertionError("fixture shape changed: the last slot does not write A4: " + mv);
		}
		println("C6000_MERGE_CALL_WINDOW_OK checks=4");
	}
}
