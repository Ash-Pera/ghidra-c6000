// SPDX-License-Identifier: Apache-2.0
package c6000;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.LanguageTranslatorAdapter;
import ghidra.util.task.TaskMonitor;

/** Re-decodes C6000 instructions after a language context-layout upgrade. */
abstract class C6000CompactHalfwordTranslation extends LanguageTranslatorAdapter {
	C6000CompactHalfwordTranslation(String id, int oldVersion, int newVersion) {
		super(new LanguageID(id), oldVersion, new LanguageID(id), newVersion);
	}

	@Override
	public boolean isValid() {
		if (!super.isValid()) return false;
		try {
			validateDefaultSpaceMap();
			return true;
		}
		catch (IncompatibleLanguageException e) {
			return false;
		}
	}

	@Override
	public void fixupInstructions(Program program, Language oldLanguage, TaskMonitor monitor)
			throws Exception {
		C6000PacketContext.prime(program, monitor);
		((ProgramDB) program).getCodeManager().reDisassembleAllInstructions(monitor);
	}
}
