// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Assumed-drained schedules on a tests/fixtures/assumed-schedule.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000AssumedScheduleAnalyzer;
import c6000.C6000AssumedSchedules;
import c6000.C6000PacketContext;
import c6000.C6000PipelineCompiler;
import c6000.C6000PipelineContracts;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class C6000AssumedScheduleTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1080L, 0x1088L, 0x10a0L, 0x10c0L, 0x10e0L };
	private static final String[] NAMES = { "pipe", "plain", "entered", "branchy", "proved", "ldread" };
	private int checks;

	private void check(boolean ok, String message) {
		if (!ok) throw new AssertionError(message);
		checks++;
	}

	private boolean active(long entry) {
		return BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
			currentProgram.getRegister("c_schedule_entry"), toAddr(entry), false));
	}

	private boolean bookmarked(long entry) {
		return currentProgram.getBookmarkManager().getBookmark(toAddr(entry), BookmarkType.WARNING,
			C6000AssumedSchedules.BOOKMARK) != null;
	}

	private c6000.C6000NativeHazardWarning.Finding hazard(Function function) throws Exception {
		return c6000.C6000NativeHazardWarning.scan(currentProgram, function);
	}

	private long sum(Function function, int n) throws Exception {
		var result = new C6000PipelineCompiler(currentProgram, function, Set.of()).compile(monitor);
		var language = (ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage();
		var arithmetic = BytesPcodeArithmetic.forLanguage(language);
		var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
		for (var register : language.getRegisters()) {
			if (!register.isProcessorContext() && register.getMinimumByteSize() == 4) {
				state.setVar(register, arithmetic.fromConst(0x5a5a5a5aL, 4));
			}
		}
		state.setVar(currentProgram.getRegister("A4"), arithmetic.fromConst(0x8000, 4));
		state.setVar(currentProgram.getRegister("B4"), arithmetic.fromConst(n, 4));
		state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
		state.setVar(toAddr(0x8000), 256, false, new byte[256]);
		for (int k = 0; k < 16; k++) {
			state.setVar(toAddr(0x8000 + 4 * k), 4, false, arithmetic.fromConst((k + 1) * 3L, 4));
		}
		var library = PcodeUseropLibrary.<byte[]>nil();
		var executor = new PcodeExecutor<byte[]>(language, arithmetic, state,
			PcodeExecutorStatePiece.Reason.EXECUTE_READ);
		var frame = executor.begin(new PcodeProgram(language, Arrays.asList(result.code()),
			library.getSymbols(language)) {});
		int steps = 0;
		while (!frame.isFinished() && steps++ < 200000) executor.step(frame, library);
		if (!frame.isFinished()) throw new AssertionError("step bound n=" + n);
		return arithmetic.toLong(state.getVar(currentProgram.getRegister("A4"),
			PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT) & 0xffffffffL;
	}

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			C6000PacketContext.prime(currentProgram, monitor);
			for (int i = 0; i < ENTRIES.length; i++) {
				disassemble(toAddr(ENTRIES[i]));
				createFunction(toAddr(ENTRIES[i]), NAMES[i]);
			}
			return;
		}
		Function pipe = getFunctionAt(toAddr(0x1000L));
		Function plain = getFunctionAt(toAddr(0x1080L));
		Function entered = getFunctionAt(toAddr(0x1088L));
		Function branchy = getFunctionAt(toAddr(0x10a0L));
		Function proved = getFunctionAt(toAddr(0x10c0L));
		Function ldread = getFunctionAt(toAddr(0x10e0L));
		check(pipe != null && plain != null && entered != null && branchy != null && proved != null &&
			ldread != null, "fixture functions missing");
		// Off by default: auto-analysis applied nothing.
		check(!new C6000AssumedScheduleAnalyzer().getDefaultEnablement(currentProgram) ||
			Boolean.getBoolean("c6000.assumeDrainedSchedules"), "analyzer enabled by default");
		for (long entry : ENTRIES) if (entry != 0x10c0L) check(!active(entry) && !bookmarked(entry), "schedule before opt-in at " + entry);
		// The default path warns where native lifting is inexact, and stays silent where it is exact.
		check(hazard(pipe) != null && hazard(pipe).reason().contains("delay window"),
			"pipe branch-in-flight not warned");
		check(hazard(ldread) != null && hazard(ldread).reason().contains("before the load"),
			"ldread result latency not warned");
		check(hazard(plain) == null && hazard(entered) == null && hazard(proved) == null,
			"a straight-line function warned");
		// A review with its own evidence stays as recorded.
		var proof = C6000PipelineContracts.review(currentProgram, proved, "test caller proof", Set.of(),
			List.of(new C6000PipelineContracts.SourceWindow(0x10c0L, 32,
				C6000PipelineContracts.sha256(getBytes(toAddr(0x10c0L), 32)))), monitor);
		C6000PipelineContracts.record(currentProgram, proved, proof, monitor);
		C6000PipelineContracts.activate(currentProgram, proved, monitor);
		// The analyzer, as an explicit opt-in.
		var log = new MessageLog();
		new C6000AssumedScheduleAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, log);
		check(active(0x1000L) && bookmarked(0x1000L), "pipe not scheduled: " + log);
		check(C6000PipelineContracts.recordedReview(currentProgram, pipe).evidence().equals(C6000AssumedSchedules.EVIDENCE),
			"pipe evidence");
		// With a schedule active, the default-path warning no longer applies.
		check(hazard(pipe) == null, "pipe still warned after its schedule activated");
		check(C6000PipelineContracts.recordedReview(currentProgram, proved).evidence().equals("test caller proof") &&
			!bookmarked(0x10c0L), "proved's own review replaced");
		check(!active(0x1088L) && !bookmarked(0x1088L) && !C6000PipelineContracts.isRecorded(currentProgram, entered) &&
			log.toString().contains("delay window"), "entered in a return window scheduled: " + log);
		check(!active(0x10a0L) && !C6000PipelineContracts.isRecorded(currentProgram, branchy) &&
			log.toString().contains("entry packet"), "branch in the entry packet scheduled: " + log);
		// The schedule sums n words with every branch and load in flight.
		for (int n : new int[] { 5, 6, 9, 16 }) {
			long expected = 3L * n * (n + 1) / 2;
			long actual = sum(pipe, n);
			check(actual == expected, "pipe n=" + n + " = " + actual + " expected " + expected);
		}
		// Idempotent: an unchanged schedule is kept, not reviewed again.
		var again = C6000AssumedSchedules.apply(currentProgram, new AddressSet(toAddr(0x1000L)), monitor);
		check(again.applied() == 0 && again.kept() == 1, "repeat " + again);
		println("C6000_ASSUMED_SCHEDULE_OK checks=" + checks);
	}
}
