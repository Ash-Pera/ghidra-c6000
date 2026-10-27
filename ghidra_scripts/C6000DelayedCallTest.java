// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check B-with-B3 calls in an auto-analysed tests/fixtures/delayed-call.py image.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class C6000DelayedCallTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		// The if/else pair is its own routine; the entry never reaches it.
		for (long entry : new long[] { 0x1040L, 0x1060L, 0x10a0L, 0x1140L, 0x1200L, 0x1280L }) {
			disassemble(toAddr(entry));
			createFunction(toAddr(entry), null);
		}
		analyzeChanges(currentProgram);
		// The near arm of a call-or-jump pair stays a jump.
		Instruction jump = getInstructionAt(toAddr(0x1068L));
		if (jump == null || jump.getFlowType().isCall() || !jump.getFlowType().isConditional() ||
			getFunctionAt(toAddr(0x1080L)) != null) {
			throw new AssertionError("jump arm at 0x1068: " + jump +
				(jump == null ? "" : " flow=" + jump.getFlowType()) +
				" function at 0x1080=" + getFunctionAt(toAddr(0x1080L)));
		}
		// A B3 set in a jump's delay slots for the call after it belongs to that call.
		for (long[] jt : new long[][] { { 0x10a0L, 0x10e0L }, { 0x1148L, 0x1180L }, { 0x120cL, 0x1240L },
			{ 0x1288L, 0x12c0L } }) {
			Instruction owner = getInstructionAt(toAddr(jt[0]));
			if (owner == null || owner.getFlowType().isCall() || !owner.getFlowType().isConditional() ||
				getFunctionAt(toAddr(jt[1])) != null) {
				throw new AssertionError("jump at " + toAddr(jt[0]) + ": " + owner +
					(owner == null ? "" : " flow=" + owner.getFlowType()) +
					" function at " + toAddr(jt[1]) + "=" + getFunctionAt(toAddr(jt[1])));
			}
		}
		// B3 past a B's window end is not its return address.
		Instruction slack = getInstructionAt(toAddr(0x1290L));
		if (slack == null || slack.getFlowType().isCall() || getFunctionAt(toAddr(0x12e0L)) != null) {
			throw new AssertionError("jump at 0x1290: " + slack +
				(slack == null ? "" : " flow=" + slack.getFlowType()) +
				" function at 0x12e0=" + getFunctionAt(toAddr(0x12e0L)));
		}
		// B3 set before a conditional jump survives its fall-through to the call after it.
		Instruction after = getInstructionAt(toAddr(0x1150L));
		Function owner2 = getFunctionContaining(toAddr(0x1158L));
		if (after == null || !after.getFlowType().isCall() || !toAddr(0x1154L).equals(after.getFallThrough()) ||
			getFunctionAt(toAddr(0x11c0L)) == null || owner2 == null ||
			!owner2.getEntryPoint().equals(toAddr(0x1140L))) {
			throw new AssertionError("call at 0x1150: " + after +
				(after == null ? "" : " flow=" + after.getFlowType() + " fallthrough=" + after.getFallThrough()) +
				" callee 0x11c0=" + getFunctionAt(toAddr(0x11c0L)) + " 0x1158 in " + owner2);
		}
		// The generic SLEIGH predicate guard also gives unpredicated register
		// branches a conditional flow type. Require it for predicated calls only.
		for (long site : new long[] { 0x1008L, 0x1018L, 0x1048L, 0x104cL, 0x106cL, 0x10b8L }) {
			Instruction call = getInstructionAt(toAddr(site));
			if (call == null || !call.getFlowType().isCall() ||
				(site >= 0x1048L && site <= 0x106cL && !call.getFlowType().isConditional()) ||
				!toAddr(site + 4).equals(call.getFallThrough())) {
				throw new AssertionError("call at " + toAddr(site) + ": " + call +
					(call == null ? "" : " flow=" + call.getFlowType() +
						" fallthrough=" + call.getFallThrough()));
			}
			boolean ref = false;
			for (Reference r : call.getReferencesFrom()) {
				ref |= r.getReferenceType().isCall() && r.getToAddress().equals(toAddr(0x1100L));
			}
			if (!ref) throw new AssertionError("no call reference to 0x1100 from " + toAddr(site));
		}
		for (long slot : new long[] { 0x100cL, 0x101cL, 0x1020L }) {
			if (getFunctionContaining(toAddr(slot)) == null ||
				!getFunctionContaining(toAddr(slot)).getEntryPoint().equals(toAddr(0x1000L))) {
				throw new AssertionError(toAddr(slot) + " is not in the caller");
			}
		}
		if (getFunctionAt(toAddr(0x1100L)) == null) {
			throw new AssertionError("callee 0x1100 is not a function");
		}
		println("C6000_DELAYED_CALL_OK");
	}
}
