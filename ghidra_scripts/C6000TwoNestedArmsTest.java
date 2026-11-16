// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Three independent nested arms from tests/fixtures/two-nested-arms.asm: arm A (carrier 0x1018)
// must carry its tail call to FA (0x1030); arm B (carrier 0x1050) is refused because enterb jumps
// into its window; arm C (carrier 0x1090) is refused because its inner guards on A1, not B0.
// Per-candidate carrying must carry A while skipping B and C.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
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
			long[] entries = {0x1000L, 0x1030L, 0x1038L, 0x1068L, 0x1070L, 0x1078L, 0x10a8L};
			String[] names = {"two_nested_arms", "fa", "bfn", "fb", "enterb", "cfn", "fc"};
			for (int i = 0; i < entries.length; i++) {
				disassemble(toAddr(entries[i]));
				Function f = createFunction(toAddr(entries[i]), names[i]);
				if (f == null) throw new AssertionError("could not create " + names[i]);
				f.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
			}
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

		Function entry = getFunctionAt(toAddr(0x1000L));
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(entry, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null)
				throw new AssertionError("decompile failed");
			String c = result.getDecompiledFunction().getC();
			if (!c.contains("fa(") || !c.contains("return;"))
				throw new AssertionError("arm A C did not preserve the tail-call and plain-return paths");
		}
		finally {
			decompiler.dispose();
		}
		println("C6000_TWO_NESTED_ARMS_OK");
	}

	private boolean carriesCallTo(Address carrier, Address callee) {
		var instruction = currentProgram.getListing().getInstructionAt(carrier);
		if (instruction == null) throw new AssertionError("missing carrier at " + carrier);
		for (Reference reference : instruction.getReferencesFrom())
			if (reference.getReferenceType().isCall() && reference.getToAddress().equals(callee)) return true;
		return false;
	}
}
