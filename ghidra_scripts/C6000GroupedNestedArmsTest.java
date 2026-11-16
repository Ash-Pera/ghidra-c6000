// SPDX-License-Identifier: Apache-2.0
// @category C6000
// A chained nested-arm pair sharing a carrier (tests/fixtures/grouped-nested-arms.asm). arm0's inner
// (0x100c) is arm1's owner, so arm0 and arm1 share the carrier at 0x1020 and must be skipped together.
// arm1 is refused because dent jumps into its window; correct carrying therefore skips arm0 too, so
// owner0 (0x1000) keeps its branch flow and carrier0 (0x1014) takes no call. A partial-group accept
// would carry arm0 alone and break both.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class C6000GroupedNestedArmsTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			long[] entries = {0x1000L, 0x1038L, 0x1040L};
			String[] names = {"grouped_nested_arms", "gd", "dent"};
			for (int i = 0; i < entries.length; i++) {
				disassemble(toAddr(entries[i]));
				Function f = createFunction(toAddr(entries[i]), names[i]);
				if (f == null) throw new AssertionError("could not create " + names[i]);
				f.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
			}
			return;
		}

		// Carrier0 at 0x1014 must take no call to GD (0x1038): the whole group was skipped.
		var carrier = currentProgram.getListing().getInstructionAt(toAddr(0x1014L));
		if (carrier == null) throw new AssertionError("missing carrier0 at 0x1014");
		for (Reference reference : carrier.getReferencesFrom())
			if (reference.getReferenceType().isCall() && reference.getToAddress().equals(toAddr(0x1038L)))
				throw new AssertionError("arm0 was carried alone: carrier0 took a call despite its groupmate being refused");
		// owner0 at 0x1000 must still own its branch flow (it was not made inert).
		var owner = currentProgram.getListing().getInstructionAt(toAddr(0x1000L));
		if (owner == null) throw new AssertionError("missing owner0 at 0x1000");
		boolean flow = false;
		for (Reference reference : owner.getReferencesFrom())
			if (reference.getReferenceType().isFlow()) flow = true;
		if (!flow) throw new AssertionError("owner0 lost its branch flow: it was carried as part of a partial group");
		println("C6000_GROUPED_NESTED_ARMS_OK");
	}
}
