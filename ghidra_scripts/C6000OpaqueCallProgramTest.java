// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Local gate model: a schedule activated under -Dc6000.opaqueCalls keeps decompiling without the
// JVM flag, because the setting is recorded with the function. In a tests/fixtures/nested-window-schedule.py
// image, after C6000NestedWindowScheduleTest.java prepare.

import c6000.C6000PipelineContracts;
import c6000.C6000PipelineSchedules;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.util.List;
import java.util.Set;

public class C6000OpaqueCallProgramTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Function f = getFunctionAt(toAddr(0x1040L));
		System.setProperty("c6000.opaqueCalls", "true");
		try {
			var review = review(f);
			C6000PipelineContracts.record(currentProgram, f, review, monitor);
			C6000PipelineContracts.activate(currentProgram, f, monitor);
		}
		finally {
			System.clearProperty("c6000.opaqueCalls");
		}
		var options = currentProgram.getOptions(C6000PipelineSchedules.OPTIONS);
		String key = C6000PipelineSchedules.opaqueCallsKey(f);
		if (!"true".equals(options.getString(key, ""))) throw new AssertionError("opaque calls not recorded with the schedule");
		// Known-good: no JVM flag, the recorded setting still compiles the opaque schedule.
		String error = decompileError(f);
		if (error != null) throw new AssertionError("recorded opaque schedule failed without the flag: " + error);
		// Known-bad: without the recorded setting the same schedule does not compile.
		options.removeOption(key);
		try {
			if (decompileError(f) == null) throw new AssertionError("schedule decompiled without opaque calls");
		}
		finally {
			options.setString(key, "true");
		}
		println("C6000_OPAQUE_CALL_PROGRAM_OK checks=3");
	}

	private C6000PipelineContracts.Review review(Function f) throws Exception {
		long start = f.getEntryPoint().getOffset() & ~31L;
		byte[] bytes = getBytes(toAddr(start), 32);
		var source = new C6000PipelineContracts.SourceWindow(start, 32, C6000PipelineContracts.sha256(bytes));
		return C6000PipelineContracts.review(currentProgram, f, "fixture entry: drained pipeline", Set.of(), List.of(source), monitor);
	}

	/** Null when the decompile completed without an error. */
	private String decompileError(Function f) {
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			DecompileResults results = decompiler.decompileFunction(f, 60, monitor);
			String message = results.getErrorMessage();
			if (!results.decompileCompleted()) return message == null || message.isBlank() ? "not completed" : message.trim();
			return message != null && message.contains("Exact C6000 schedule") ? message.trim() : null;
		}
		finally {
			decompiler.dispose();
		}
	}
}
