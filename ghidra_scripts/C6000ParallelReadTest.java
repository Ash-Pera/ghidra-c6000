// SPDX-License-Identifier: Apache-2.0
// @category C6000
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.BytesPcodeExecutorState;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.pcode.exec.PcodeStateCallbacks;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class C6000ParallelReadTest extends GhidraScript {
	private BytesPcodeArithmetic arithmetic;
	private final List<String> failures = new ArrayList<>();

	private void check(boolean ok, String message) {
		if (!ok) failures.add(message);
	}

	private Address address(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private Instruction instruction(long offset) throws Exception {
		Address at = address(offset);
		Instruction result = getInstructionAt(at);
		if (result == null) {
			result = parseInstruction(offset);
		}
		return result;
	}

	private Instruction parseInstruction(long offset) throws Exception {
		Address at = address(offset);
		var processor = new ProcessorContextImpl(currentProgram.getLanguage());
		var registerValue = currentProgram.getProgramContext().getRegisterValue(
			currentProgram.getLanguage().getContextBaseRegister(), at);
		if (registerValue != null) processor.setRegisterValue(registerValue);
		var memory = new DumbMemBufferImpl(currentProgram.getMemory(), at);
		var prototype = currentProgram.getLanguage().parse(memory, processor, false);
		return new PseudoInstruction(currentProgram, at, prototype, memory, processor);
	}

	private BytesPcodeExecutorState state(JsonObject input) {
		BytesPcodeExecutorState result =
			new BytesPcodeExecutorState(currentProgram.getLanguage(), PcodeStateCallbacks.NONE);
		for (Register register : currentProgram.getLanguage().getRegisters()) {
			if (!register.isProcessorContext() && register.getMinimumByteSize() == 4) {
				result.setVar(register, arithmetic.fromConst(0, 4));
			}
		}
		for (var item : input.entrySet()) {
			result.setVar(currentProgram.getRegister(item.getKey()),
				arithmetic.fromConst(item.getValue().getAsLong(), 4));
		}
		return result;
	}

	private void execute(Instruction instruction, BytesPcodeExecutorState state,
			String name) {
		var language = (ghidra.app.plugin.processors.sleigh.SleighLanguage)
			currentProgram.getLanguage();
		var library = PcodeUseropLibrary.<byte[]>nil();
		var executor = new PcodeExecutor<byte[]>(language, arithmetic, state,
			PcodeExecutorStatePiece.Reason.EXECUTE_READ);
		var program = new PcodeProgram(language,
			Arrays.asList(instruction.getPcode(false)), library.getSymbols(language)) {};
		var frame = executor.begin(program);
		int steps = 0;
		while (!frame.isFinished() && steps++ < 10000) executor.step(frame, library);
		if (!frame.isFinished()) throw new AssertionError("P-code step bound: " + name);
	}

	private long value(BytesPcodeExecutorState state, String name) {
		return arithmetic.toLong(state.getVar(currentProgram.getRegister(name),
			PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT) &
			0xffffffffL;
	}

	private void runLinear(JsonObject row) throws Exception {
		String name = row.get("name").getAsString();
		var input = row.getAsJsonObject("input");
		var state = state(input);
		for (var element : row.getAsJsonArray("sequence")) {
			long pc = element.getAsLong();
			execute(instruction(pc), state, name + "@" + Long.toHexString(pc));
		}
		var observed = new JsonObject();
		for (var expected : row.getAsJsonObject("expected").entrySet()) {
			long actual = value(state, expected.getKey());
			long wanted = expected.getValue().getAsLong() & 0xffffffffL;
			observed.addProperty(expected.getKey(), actual);
			check(actual == wanted, name + " " + expected.getKey() + "=" +
				Long.toHexString(actual) + " expected=" + Long.toHexString(wanted));
		}
		println("PARALLEL_READ_RESULT " + name + " " + observed);
	}

	private boolean overlaps(Register register, Varnode node) {
		if (node == null || !node.isRegister() ||
			node.getAddress().getAddressSpace() != register.getAddress().getAddressSpace()) {
			return false;
		}
		long start = node.getOffset();
		long end = start + node.getSize();
		long registerStart = register.getAddress().getOffset();
		long registerEnd = registerStart + register.getMinimumByteSize();
		return start < registerEnd && registerStart < end;
	}

	private void checkBranchDelay(JsonObject row) throws Exception {
		long entry = row.get("entry").getAsLong();
		long branchPc = entry + 4;
		Address branchAt = address(branchPc);
		currentProgram.getProgramContext().setValue(currentProgram.getRegister("c_flow_delay"),
			branchAt, branchAt, BigInteger.valueOf(row.get("delay_bytes").getAsInt()));
		Instruction branch = parseInstruction(branchPc);
		Register tested = currentProgram.getRegister("B1");
		Register delayed = currentProgram.getRegister("B6");
		int read = -1;
		int commit = -1;
		int delayWrite = -1;
		PcodeOp[] code = branch.getPcode(false);
		for (int index = 0; index < code.length; index++) {
			PcodeOp op = code[index];
			if (read < 0) {
				for (Varnode input : op.getInputs()) {
					if (overlaps(tested, input)) {
						read = index;
						break;
					}
				}
			}
			if (commit < 0 && overlaps(tested, op.getOutput())) commit = index;
			if (delayWrite < 0 && overlaps(delayed, op.getOutput())) delayWrite = index;
		}
		println("PARALLEL_READ_BRANCH_PCODE " + branch + " context=" +
			context("c_pkt_active", branchPc) + "/" +
			context("c_pkt_branch_end", branchPc) + "/" +
			context("c_pkt_pred", branchPc) + "/" +
			context("c_pkt_write0", branchPc) + "/" +
			Arrays.toString(code));
		check(branch.getMnemonicString().contains("B.S2"),
			"branch-terminal decoded as " + branch);
		check(read >= 0, "branch does not read B1");
		check(commit > read, "B1 packet commit is missing or precedes branch read");
		check(delayWrite > commit, "delay-slot B6 write does not follow B1 commit");
		println("PARALLEL_READ_BRANCH read=" + read + " commit=" + commit +
			" delayWrite=" + delayWrite);
	}

	private void addJumpReference(JsonObject jump) {
		Address source = address(jump.get("source").getAsLong());
		Address target = address(jump.get("target").getAsLong());
		for (var reference : currentProgram.getReferenceManager().getReferencesFrom(source)) {
			if (reference.getToAddress().equals(target)) return;
		}
		currentProgram.getReferenceManager().addMemoryReference(source, target,
			RefType.UNCONDITIONAL_JUMP, SourceType.ANALYSIS, 0);
	}

	private BigInteger context(String field, long pc) {
		Register register = currentProgram.getRegister(field);
		return register == null ? null :
			currentProgram.getProgramContext().getValue(register, address(pc), false);
	}

	private void checkJump(JsonObject jump, boolean late) throws Exception {
		String name = jump.get("name").getAsString();
		long writer = jump.get("packet").getAsLong();
		check(currentProgram.getRegister("c_pkt_active") != null &&
			currentProgram.getRegister("c_pkt_write0") != null &&
			currentProgram.getRegister("c_pkt_write1") != null,
			"parallel-read context fields missing for " + name);
		BigInteger before = context("c_pkt_active", writer);
		if (!late) check(before == null || before.signum() == 0,
			name + " was not refused during prime: " + before);
		if (late) {
			try {
				Method audit = C6000PacketContext.class.getMethod("audit",
					ghidra.program.model.listing.Program.class,
					ghidra.util.task.TaskMonitor.class);
				int refused = (Integer) audit.invoke(null, currentProgram, monitor);
				check(refused > 0, "post-analysis audit did not refuse " + name);
			}
			catch (NoSuchMethodException missing) {
				check(false, "post-analysis packet audit is missing");
			}
		}
		BigInteger after = context("c_pkt_active", writer);
		BigInteger write0 = context("c_pkt_write0", writer);
		BigInteger write1 = context("c_pkt_write1", writer);
		check(after == null || after.signum() == 0,
			name + " retained packet deferral, before=" + before + " after=" + after);
		check(write0 == null || write0.signum() == 0,
			name + " retained first deferred writer: " + write0);
		check(write1 == null || write1.signum() == 0,
			name + " retained second deferred writer: " + write1);
		println("PARALLEL_READ_JUMP " + name + " before=" + before + " after=" + after);
	}

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length != 1) throw new IllegalArgumentException("expected cases.json");
		JsonObject cases = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0])))
			.getAsJsonObject();
		var jumps = cases.getAsJsonArray("jumps");
		addJumpReference(jumps.get(0).getAsJsonObject());
		int packets = C6000PacketContext.prime(currentProgram, monitor);
		arithmetic = BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());
		checkJump(jumps.get(0).getAsJsonObject(), false);
		for (var element : cases.getAsJsonArray("runs")) runLinear(element.getAsJsonObject());
		checkBranchDelay(cases.getAsJsonObject("branch"));
		JsonObject late = jumps.get(1).getAsJsonObject();
		instruction(late.get("source").getAsLong());
		addJumpReference(late);
		checkJump(late, true);
		if (!failures.isEmpty()) throw new AssertionError(String.join("; ", failures));
		println("C6000_PARALLEL_READ_OK runs=" + cases.getAsJsonArray("runs").size() +
			" jumps=" + jumps.size() + " packets=" + packets);
	}
}
