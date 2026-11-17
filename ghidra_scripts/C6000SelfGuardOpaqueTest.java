// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Local gate model (-Dc6000.opaqueCalls): a software-pipelined countdown loop whose [A1] SUB A1 cannot revive a
// zero A1, so its call lands once, after the loop; in a tests/fixtures/pipeline-selfguard-opaque.py image (local: upstream #75 replaced this fixture).

import c6000.C6000PacketContext;
import c6000.C6000PipelineCompiler;
import c6000.C6000PipelineContracts;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.*;

public class C6000SelfGuardOpaqueTest extends GhidraScript {
	private static final String EVIDENCE = "fixture entry: drained pipeline";

	private static final class Case {
		String name;
		long at;
		long body_end;
		long callee;
		long callee_end;
		long link;
		long kernel;
		int[] kernel_truths;
		boolean accepted;
	}

	@Override
	protected void run() throws Exception {
		var cases = new com.google.gson.Gson().fromJson(Files.readString(Paths.get(getScriptArgs()[0])), Case[].class);
		C6000PacketContext.prime(currentProgram, monitor);
		int accepted = 0, refused = 0, executions = 0;
		System.setProperty("c6000.opaqueCalls", "true");
		try {
			for (var item : cases) {
				Function function = prepare(item);
				kernelTruths(item, function);
				C6000PipelineContracts.Review review;
				try {
					review = review(function);
				}
				catch (IllegalArgumentException error) {
					println((item.accepted ? "UNEXPECTED_REFUSAL " : "EXPECTED_REFUSAL ") + item.name + ": " + error.getMessage());
					if (item.accepted || !error.getMessage().contains("opaque call lacks an exact B3 link proof"))
						throw new AssertionError(item.name + ": " + error.getMessage(), error);
					refused++;
					continue;
				}
				if (!item.accepted) throw new AssertionError("accepted " + item.name);
				C6000PipelineContracts.record(currentProgram, function, review, monitor);
				var schedule = C6000PipelineContracts.activate(currentProgram, function, monitor);
				println("SUPPORTED " + item.name + " states=" + schedule.states());
				for (long n : new long[] {0, 1, 2, 3, 7}) {
					execute(item, schedule, n);
					executions++;
				}
				decompiledCallAfterLoop(item, function);
				accepted++;
			}
		}
		finally {
			System.clearProperty("c6000.opaqueCalls");
		}
		println("C6000_SELFGUARD_OPAQUE_OK accepted=" + accepted + " refused=" + refused + " executions=" + executions);
	}

	private Function prepare(Case item) throws Exception {
		var body = new AddressSet(toAddr(item.at), toAddr(item.body_end));
		var callee = new AddressSet(toAddr(item.callee), toAddr(item.callee_end));
		if (!new DisassembleCommand(toAddr(item.at), body, false).applyTo(currentProgram, monitor) ||
			!new DisassembleCommand(toAddr(item.callee), callee, false).applyTo(currentProgram, monitor))
			throw new IllegalStateException("Could not disassemble " + item.name);
		currentProgram.getFunctionManager().createFunction(item.name + "_callee", toAddr(item.callee), callee, SourceType.USER_DEFINED);
		return currentProgram.getFunctionManager().createFunction(item.name, toAddr(item.at), body, SourceType.USER_DEFINED);
	}

	private C6000PipelineContracts.Review review(Function function) throws Exception {
		long start = function.getEntryPoint().getOffset();
		var source = new C6000PipelineContracts.SourceWindow(start, 32, C6000PipelineContracts.sha256(getBytes(toAddr(start), 32)));
		return C6000PipelineContracts.review(currentProgram, function, EVIDENCE, Set.of(), List.of(source), monitor);
	}

	/** The A1 truths of the compile's states at the kernel: zero only where the decrement is [A1] (SPRUFE8B 3.5). */
	private void kernelTruths(Case item, Function function) throws Exception {
		var compiler = new C6000PipelineCompiler(currentProgram, function);
		try {
			compiler.compile();
		}
		catch (IllegalArgumentException error) {
			// The refusal is checked by review; the states explored so far are kept.
		}
		var field = C6000PipelineCompiler.class.getDeclaredField("states");
		field.setAccessible(true);
		Set<Integer> truths = new TreeSet<>();
		for (Object state : ((Map<?, ?>) field.get(compiler)).keySet()) {
			if (((Number) component(state, "pc")).longValue() != item.kernel) continue;
			var values = (List<?>) component(component(state, "facts"), "values");
			truths.add(((Number) component(values.get(1), "truth")).intValue());
		}
		Set<Integer> expected = new TreeSet<>();
		for (int truth : item.kernel_truths) expected.add(truth);
		if (!truths.equals(expected)) throw new AssertionError(item.name + ": A1 truths at the kernel " + truths + ", want " + expected);
	}

	private static Object component(Object target, String name) throws Exception {
		var method = target.getClass().getDeclaredMethod(name);
		method.setAccessible(true);
		return method.invoke(target);
	}

	/** n = A4: the kernel runs max(n, 1) + 1 times (the entry branch lands once), then one call with B3 at the link. */
	private void execute(Case item, C6000PipelineCompiler.Result schedule, long n) throws Exception {
		var language = (SleighLanguage) currentProgram.getLanguage();
		var arithmetic = BytesPcodeArithmetic.forLanguage(language);
		var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
		for (var register : language.getRegisters())
			if (!register.isProcessorContext() && register.getMinimumByteSize() == 4) state.setVar(register, arithmetic.fromConst(0, 4));
		state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
		state.setVar(currentProgram.getRegister("A4"), arithmetic.fromConst(n, 4));
		var reason = PcodeExecutorStatePiece.Reason.INSPECT;
		var purpose = PcodeArithmetic.Purpose.INSPECT;
		List<long[]> calls = new ArrayList<>();
		var executor = new PcodeExecutor<byte[]>(language, arithmetic, state, PcodeExecutorStatePiece.Reason.EXECUTE_READ) {
			@Override
			public void executeCall(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<byte[]> library) {
				calls.add(new long[] {op.getInput(0).getOffset(), arithmetic.toLong(state.getVar(currentProgram.getRegister("B3"), reason), purpose),
					arithmetic.toLong(state.getVar(currentProgram.getRegister("A4"), reason), purpose)});
			}
		};
		var library = PcodeUseropLibrary.<byte[]>nil();
		var frame = executor.begin(new PcodeProgram(language, Arrays.asList(schedule.code()), library.getSymbols(language)) {});
		int steps = 0;
		while (!frame.isFinished() && steps++ < 200000) executor.step(frame, library);
		if (!frame.isFinished()) throw new AssertionError(item.name + " n=" + n + " exceeded step bound");
		if (calls.size() != 1 || calls.get(0)[0] != item.callee || calls.get(0)[1] != item.link || calls.get(0)[2] != Math.max(n, 1) + 1)
			throw new AssertionError(item.name + " n=" + n + ": calls " + calls.stream().map(Arrays::toString).toList());
		long pc = arithmetic.toLong(state.getVar(currentProgram.getRegister("PC"), reason), purpose);
		long a1 = arithmetic.toLong(state.getVar(currentProgram.getRegister("A1"), reason), purpose);
		if (pc != 0x9000 || a1 != 0) throw new AssertionError(item.name + " n=" + n + ": PC=" + Long.toHexString(pc) + " A1=" + a1);
	}

	/** One decompiled CALL, to the callee, in a block on no cycle that a cycle reaches. */
	private void decompiledCallAfterLoop(Case item, Function function) throws Exception {
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var results = decompiler.decompileFunction(function, 60, monitor);
			if (!results.decompileCompleted() || results.getHighFunction() == null) throw new AssertionError(item.name + ": decompile " + results.getErrorMessage());
			var blocks = results.getHighFunction().getBasicBlocks();
			List<PcodeOpAST> calls = new ArrayList<>();
			var ops = results.getHighFunction().getPcodeOps();
			while (ops.hasNext()) {
				var op = ops.next();
				if (op.getOpcode() == PcodeOp.CALLIND) throw new AssertionError(item.name + ": decompiled CALLIND " + op);
				if (op.getOpcode() == PcodeOp.CALL) calls.add(op);
			}
			if (calls.size() != 1 || calls.get(0).getInput(0).getOffset() != item.callee)
				throw new AssertionError(item.name + ": decompiled calls " + calls + "\n" + results.getDecompiledFunction().getC());
			var call = calls.get(0).getParent();
			boolean loop = false;
			for (var block : blocks) loop |= reaches(block, block) && reaches(block, call);
			if (reaches(call, call) || !loop)
				throw new AssertionError(item.name + ": call is not after the loop\n" + results.getDecompiledFunction().getC());
			println("DECOMPILED " + item.name + ":\n" + results.getDecompiledFunction().getC());
		}
		finally {
			decompiler.dispose();
		}
	}

	/** True when to is reachable from from by one or more edges. */
	private static boolean reaches(PcodeBlockBasic from, PcodeBlockBasic to) {
		Deque<PcodeBlock> work = new ArrayDeque<>();
		Set<PcodeBlock> seen = new HashSet<>();
		for (int k = 0; k < from.getOutSize(); k++) work.add(from.getOut(k));
		while (!work.isEmpty()) {
			var block = work.pop();
			if (block == to) return true;
			if (!seen.add(block)) continue;
			for (int k = 0; k < block.getOutSize(); k++) work.add(block.getOut(k));
		}
		return false;
	}
}
