// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check stacked predicated return windows in a tests/fixtures/stacked-return-windows.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class C6000StackedReturnWindowsTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			disassemble(toAddr(0x1000L));
			createFunction(toAddr(0x1000L), "stacked");
			disassemble(toAddr(0x1038L));
			createFunction(toAddr(0x1038L), "far");
			return;
		}
		Function f = getFunctionAt(toAddr(0x1000L));
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null)
				throw new AssertionError("decompile failed: " + (result == null ? "null" : result.getErrorMessage()));
			String c = result.getDecompiledFunction().getC();
			// Each path: the first return returns 1 and clears p[4]; the second returns 0; the jump reaches far.
			boolean returnsOne = c.matches("(?s).*return 1;.*");
			boolean returnsZero = c.matches("(?s).*return 0;.*");
			boolean clearsSlot = c.matches("(?s).*in_B0\\s*=\\s*0;.*\\*\\(undefined4 \\*\\)[^;]*=\\s*in_B0;.*");
			boolean reachesFar = c.matches("(?s).*return 9;.*");
			if (!returnsOne || !returnsZero || !clearsSlot || !reachesFar) {
				throw new AssertionError("stacked returns lost a path: one=" + returnsOne + " zero=" +
					returnsZero + " store=" + clearsSlot + " far=" + reachesFar);
			}
		}
		finally {
			decompiler.dispose();
		}
		println("C6000_STACKED_RETURN_WINDOWS_OK");
	}
}
