// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check a nested tail-call/return arm assembled from tests/fixtures/nested-return-arm.asm.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.VoidDataType;

public class C6000NestedReturnArmTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			disassemble(toAddr(0x1000L));
			Function entry = createFunction(toAddr(0x1000L), "nested_return_arm");
			if (entry == null) throw new AssertionError("could not create entry function");
			entry.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
			disassemble(toAddr(0x1030L));
			Function callee = createFunction(toAddr(0x1030L), "f");
			if (callee == null) throw new AssertionError("could not create F function");
			callee.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
			return;
		}

		Function entry = getFunctionAt(toAddr(0x1000L));
		Function callee = getFunctionAt(toAddr(0x1030L));
		if (entry == null || callee == null) throw new AssertionError("missing fixture function");
		var carrier = currentProgram.getListing().getInstructionAt(toAddr(0x1018L));
		if (carrier == null) throw new AssertionError("missing nested carry carrier");
		boolean callReference = false;
		for (Reference reference : carrier.getReferencesFrom()) {
			if (reference.getReferenceType().isCall() &&
					reference.getToAddress().equals(callee.getEntryPoint())) callReference = true;
		}
		if (!callReference) throw new AssertionError("carrier lost its tail-call reference");

		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(entry, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null)
				throw new AssertionError("decompile failed");
			String c = result.getDecompiledFunction().getC();
			if (!c.contains("f(") || !c.contains("return;"))
				throw new AssertionError("C did not preserve the tail-call and plain-return paths");
		}
		finally {
			decompiler.dispose();
		}
		println("C6000_NESTED_RETURN_ARM_OK");
	}
}
