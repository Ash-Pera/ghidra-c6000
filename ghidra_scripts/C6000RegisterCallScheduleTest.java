// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Local gate model (-Dc6000.opaqueCalls): register-target B in exact schedules, in a tests/fixtures/register-call.py
// image after C6000RegisterCallTest.java prepare. A target the schedule proves constant is a direct CALL; any other is
// a CALLIND of the value the branch read at E1, resuming at the proved B3 link, or a tail call for a computed jump.

import c6000.C6000PipelineCompiler;
import c6000.C6000PipelineContracts;
import c6000.C6000PipelineSchedules;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class C6000RegisterCallScheduleTest extends GhidraScript {
	private int checks;

	@Override
	protected void run() throws Exception {
		System.setProperty("c6000.opaqueCalls", "true");
		try {
			// A proved constant target is a direct call; two of them keep their own targets (the decompiler keys an
			// indirect-call override by instruction address, and every scheduled op shares the entry's).
			calls(0x1040L, List.of(0x10e0L), 0);
			calls(0x1100L, List.of(0x10e0L, 0x1180L), 0);
			decompiledCalls(0x1100L, List.of(0x10e0L, 0x1180L));
			// A predicated call and a tail transfer through a constant (B3 untouched).
			calls(0x10a0L, List.of(0x10e0L), 0);
			calls(0x1080L, List.of(0x10e0L), 0);
			// A function pointer: CALLIND of A4 as read at E1, before ADD 1,B4,A4 in the slots.
			capturedAtIssue(0x1000L, 0x1004L, "A4");
			// A computed jump with B3 untouched: a tail CALLIND of A1 at E1.
			capturedAtIssue(0x1160L, 0x1168L, "A1");
			tail(0x1160L);
			// The listing returns through the entry copy of B3 in caller-saved A0 (C6000ReturnAnalyzer): a listed return is a
			// return (SPEC R2), although the clobber model hashed A0 across the call.
			calls(0x1140L, List.of(0x10e0L), 0);
			// The same with the copy after the entry packet, also once enabling has rewritten the entry (bind recompiles).
			calls(0x11e0L, List.of(0x10e0L), 0);
			C6000PipelineSchedules.enable(currentProgram, getFunctionAt(toAddr(0x11e0L)), "fixture entry: drained pipeline", Set.of(), monitor);
			checks++;
			// Two writers of A0: no listed return, and the copy does not survive the call (gate clobber model), so B A0 is
			// a tail CALLIND, as the native decompile and the reference (SPEC R7a) take an unrecovered computed jump.
			calls(0x1200L, List.of(0x10e0L), 1);
			tail(0x1200L);
			// A fresh link that is no sequential return point: the callee returns there (SPEC R3), no tail call. Natively
			// the branch is no call, so the return point is declared part of the function, as ELF symbol sizes would.
			disassemble(toAddr(0x11b8L));
			getFunctionAt(toAddr(0x11a0L)).setBody(new ghidra.program.model.address.AddressSet(toAddr(0x11a0L), toAddr(0x11c3L)));
			capturedAtIssue(0x11a0L, 0x11a4L, "A4");
			resumes(0x11a0L);
		}
		finally {
			System.clearProperty("c6000.opaqueCalls");
		}
		println("C6000_REGISTER_CALL_SCHEDULE_OK checks=" + checks);
	}

	private C6000PipelineCompiler.Result schedule(long entry) throws Exception {
		Function f = getFunctionAt(toAddr(entry));
		if (f == null) throw new AssertionError("no function at " + toAddr(entry));
		long start = entry & ~31L;
		byte[] bytes = getBytes(toAddr(start), 32);
		var source = new C6000PipelineContracts.SourceWindow(start, 32, C6000PipelineContracts.sha256(bytes));
		C6000PipelineContracts.review(currentProgram, f, "fixture entry: drained pipeline", Set.of(), List.of(source), monitor);
		return new C6000PipelineCompiler(currentProgram, f, Set.of()).compile(monitor);
	}

	/** Every CALLIND is a tail call: the op before it sets the return value from B3 (no continuation). */
	private void tail(long entry) throws Exception {
		var code = schedule(entry).code();
		var ret = currentProgram.getRegister("C6000_PIPE_RET");
		for (int i = 0; i < code.length; i++) {
			if (code[i].getOpcode() != PcodeOp.CALLIND) continue;
			var out = i > 0 ? code[i - 1].getOutput() : null;
			if (out == null || !out.isRegister() || out.getOffset() != ret.getOffset()) throw new AssertionError(toAddr(entry) + ": CALLIND " + i + " resumes, want a tail call");
		}
		checks++;
	}

	/** Every CALLIND resumes in the function (no tail call). */
	private void resumes(long entry) throws Exception {
		var code = schedule(entry).code();
		var ret = currentProgram.getRegister("C6000_PIPE_RET");
		for (int i = 0; i < code.length; i++) {
			if (code[i].getOpcode() != PcodeOp.CALLIND) continue;
			var out = i > 0 ? code[i - 1].getOutput() : null;
			if (out != null && out.isRegister() && out.getOffset() == ret.getOffset()) throw new AssertionError(toAddr(entry) + ": CALLIND " + i + " is a tail call, want it to resume");
		}
		checks++;
	}

	/** Direct CALL targets in p-code order equal targets, and the schedule holds indirect CALLINDs. */
	private void calls(long entry, List<Long> targets, int indirect) throws Exception {
		var code = schedule(entry).code();
		List<Long> seen = new ArrayList<>();
		int ind = 0;
		for (PcodeOp op : code) {
			if (op.getOpcode() == PcodeOp.CALL) seen.add(op.getInput(0).getOffset());
			if (op.getOpcode() == PcodeOp.CALLIND) ind++;
		}
		if (!seen.equals(targets) || ind != indirect) {
			throw new AssertionError(toAddr(entry) + ": CALL " + hex(seen) + " CALLIND " + ind + ", want " + hex(targets) + " / " + indirect);
		}
		checks++;
	}

	/** The decompiled function calls targets in order. */
	private void decompiledCalls(long entry, List<Long> targets) throws Exception {
		Function f = getFunctionAt(toAddr(entry));
		var review = C6000PipelineContracts.review(currentProgram, f, "fixture entry: drained pipeline", Set.of(),
			List.of(new C6000PipelineContracts.SourceWindow(entry & ~31L, 32, C6000PipelineContracts.sha256(getBytes(toAddr(entry & ~31L), 32)))), monitor);
		C6000PipelineContracts.record(currentProgram, f, review, monitor);
		C6000PipelineContracts.activate(currentProgram, f, monitor);
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var results = decompiler.decompileFunction(f, 60, monitor);
			if (!results.decompileCompleted() || results.getHighFunction() == null) throw new AssertionError("decompile " + results.getErrorMessage());
			List<Long> seen = new ArrayList<>();
			var ops = results.getHighFunction().getPcodeOps();
			List<PcodeOpAST> all = new ArrayList<>();
			while (ops.hasNext()) all.add(ops.next());
			all.sort((a, b) -> a.getSeqnum().compareTo(b.getSeqnum()));
			for (PcodeOpAST op : all) {
				if (op.getOpcode() == PcodeOp.CALLIND) throw new AssertionError(toAddr(entry) + ": decompiled CALLIND " + op);
				if (op.getOpcode() == PcodeOp.CALL) seen.add(op.getInput(0).getOffset());
			}
			if (!seen.equals(targets)) throw new AssertionError(toAddr(entry) + ": decompiled calls " + hex(seen) + ", want " + hex(targets));
		}
		finally {
			decompiler.dispose();
		}
		checks++;
	}

	/** One CALLIND, no CALL; its target is a COPY chain from the register read in the cycle that issues branch. */
	private void capturedAtIssue(long entry, long branch, String register) throws Exception {
		var result = schedule(entry);
		var code = result.code();
		Map<Varnode, Integer> def = new java.util.HashMap<>();
		PcodeOp call = null;
		int calls = 0;
		for (int i = 0; i < code.length; i++) {
			if (code[i].getOutput() != null && code[i].getOutput().isUnique()) def.putIfAbsent(code[i].getOutput(), i);
			if (code[i].getOpcode() == PcodeOp.CALLIND) { if (call != null) throw new AssertionError(toAddr(entry) + ": two CALLINDs"); call = code[i]; }
			if (code[i].getOpcode() == PcodeOp.CALL) calls++;
		}
		if (call == null || calls != 0) throw new AssertionError(toAddr(entry) + ": CALLIND " + call + ", CALL " + calls);
		Varnode v = call.getInput(0);
		int at = -1;
		for (int hops = 0; v.isUnique() && hops < 64; hops++) {
			Integer d = def.get(v);
			if (d == null || code[d].getOpcode() != PcodeOp.COPY) throw new AssertionError(toAddr(entry) + ": target " + v + " not a COPY chain");
			v = code[d].getInput(0);
			at = d;
		}
		var reg = currentProgram.getRegister(register);
		if (!v.isRegister() || v.getOffset() != reg.getOffset()) throw new AssertionError(toAddr(entry) + ": target from " + v + ", want " + register);
		long cycle = -1;
		for (var e : result.cycleStarts().entrySet()) if (e.getKey() <= at && (cycle < 0 || e.getKey() > cycle)) cycle = e.getKey();
		if (cycle < 0 || result.cycleStarts().get((int) cycle) != branch) {
			throw new AssertionError(toAddr(entry) + ": target read in the cycle of " + (cycle < 0 ? "none" : toAddr(result.cycleStarts().get((int) cycle))) + ", want " + toAddr(branch));
		}
		checks++;
	}

	private static String hex(List<Long> v) {
		StringBuilder b = new StringBuilder("[");
		for (long x : v) b.append(b.length() > 1 ? " " : "").append(Long.toHexString(x));
		return b.append(']').toString();
	}
}
