// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Three independent nested arms from tests/fixtures/two-nested-arms.asm: arm A (carrier 0x1018)
// must carry its tail call to FA (0x1030); arm B (carrier 0x1050) is refused because enterb jumps
// into its window; arm C (carrier 0x1090) is refused because its inner guards on A1, not B0.
// Per-candidate carrying must carry A while skipping B and C. Arm E (carrier 0x10d0) has no function
// at first, so it is skipped; once its function exists a later pass carries it, and A is not carried twice.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import c6000.C6000DelaySlots;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class C6000TwoNestedArmsTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			long[] entries = {0x10b0L, 0x1000L, 0x1030L, 0x1038L, 0x1068L, 0x1070L, 0x1078L, 0x10a8L};
			String[] names = {"gate", "two_nested_arms", "fa", "bfn", "fb", "enterb", "cfn", "fc"};
			for (int i = 0; i < entries.length; i++) {
				disassemble(toAddr(entries[i]));
				Function f = createFunction(toAddr(entries[i]), names[i]);
				if (f == null) throw new AssertionError("could not create " + names[i]);
				f.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
			}
			disassemble(toAddr(0x10b8L));
			Function fe = createFunction(toAddr(0x10e8L), "fe");
			if (fe == null) throw new AssertionError("could not create fe");
			fe.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
			return;
		}

		// Arm A carried: its carrier at 0x1018 holds a tail-call reference to FA (0x1030).
		if (!carriesCallTo(toAddr(0x1018L), toAddr(0x1030L)))
			throw new AssertionError("arm A was not carried: 0x1018 lost its tail-call reference to FA");
		// Arm B refused (entered window): carrier 0x1050 must not carry a call to FB (0x1068).
		if (carriesCallTo(toAddr(0x1050L), toAddr(0x1068L)))
			throw new AssertionError("arm B was carried despite its entered window");
		// Arm C refused (inner not proven false on taken): carrier 0x1090 must not carry a call to FC.
		if (carriesCallTo(toAddr(0x1090L), toAddr(0x10a8L)))
			throw new AssertionError("arm C was carried despite an independent inner predicate");

		// Arm E has no function yet, so it was skipped, not carried.
		if (getFunctionContaining(toAddr(0x10bcL)) != null)
			throw new AssertionError("arm E unexpectedly gained a function during analysis");
		if (carriesCallTo(toAddr(0x10d0L), toAddr(0x10e8L)))
			throw new AssertionError("arm E was carried without a function");
		String payloadA = currentProgram.getOptions("C6000 Nested Delay Carries").getString("carry.1018", "");
		if (payloadA.isEmpty()) throw new AssertionError("arm A has no carry payload");
		Function efn = createFunction(toAddr(0x10b8L), "efn");
		if (efn == null) throw new AssertionError("could not create efn");
		efn.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
		C6000DelaySlots.recover(currentProgram, monitor, new MessageLog());
		// A later pass picks E up once its function exists.
		if (!carriesCallTo(toAddr(0x10d0L), toAddr(0x10e8L)))
			throw new AssertionError("arm E was not carried once its function existed");
		// A carried candidate is not re-processed: A's payload and its single call reference are unchanged.
		if (!payloadA.equals(currentProgram.getOptions("C6000 Nested Delay Carries").getString("carry.1018", "")))
			throw new AssertionError("arm A was re-carried by the later pass");
		if (callsTo(toAddr(0x1018L), toAddr(0x1030L)) != 1)
			throw new AssertionError("arm A's carrier holds " + callsTo(toAddr(0x1018L), toAddr(0x1030L)) + " call references");

		Function entry = getFunctionAt(toAddr(0x1000L));
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(entry, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null)
				throw new AssertionError("decompile failed");
			String c = result.getDecompiledFunction().getC();
			String callee = getFunctionAt(toAddr(0x1030L)).getName();
			if (!c.matches("(?s).*== 0\\) \\{\\s*" + callee + "\\(\\);\\s*return;.*"))
				throw new AssertionError("arm A C did not call FA on the owner's taken path, then return");
		}
		finally {
			decompiler.dispose();
		}
		println("C6000_TWO_NESTED_ARMS_OK");
	}

	private boolean carriesCallTo(Address carrier, Address callee) {
		return callsTo(carrier, callee) > 0;
	}

	private int callsTo(Address carrier, Address callee) {
		var instruction = currentProgram.getListing().getInstructionAt(carrier);
		if (instruction == null) throw new AssertionError("missing carrier at " + carrier);
		int count = 0;
		for (Reference reference : instruction.getReferencesFrom())
			if (reference.getReferenceType().isCall() && reference.getToAddress().equals(callee)) count++;
		return count;
	}
}
