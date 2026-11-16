// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Native load-result deferral against hardware values (SPRUFE8B 3.4, 3.6, 4.2.5); fixture tests/fixtures/native-load-latency.py.
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.BytesPcodeExecutorState;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.pcode.exec.PcodeStateCallbacks;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

public class C6000NativeLoadLatencyTest extends GhidraScript {
	private static final String WARNING = "C6000 Inexact Native Pipeline";
	private static final long OLD = 0x0BADF00DL;
	// Decompiled C of the no-hazard functions at 7015913, before native deferral existed.
	private static final Map<String, String> BASE_C = Map.of(
		"ldw_after", "undefined4 ldw_after(uint param_1) { return *(undefined4 *)(param_1 & 0xfffffffc); }",
		"swap_packet", "int swap_packet(int param_1) { int in_A5; return in_A5 + param_1; }");

	private BytesPcodeArithmetic arithmetic;
	private SleighLanguage language;
	private final List<String> failures = new ArrayList<>();

	private Address address(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private void prepare(JsonArray cases) throws Exception {
		C6000PacketContext.prime(currentProgram, monitor);
		for (var element : cases) {
			JsonObject row = element.getAsJsonObject();
			String name = row.get("name").getAsString();
			if (row.has("source")) {
				define(name + "_source", row.get("source").getAsLong(), row.get("source_length").getAsLong());
			}
			define(name, row.get("entry").getAsLong(), row.get("length").getAsLong());
		}
	}

	private void define(String name, long entry, long length) throws Exception {
		Address at = address(entry);
		AddressSet body = new AddressSet(at, at.add(length - 1));
		if (!new DisassembleCommand(at, body, false).applyTo(currentProgram, monitor)) {
			throw new AssertionError("cannot disassemble " + name + " at " + at);
		}
		currentProgram.getFunctionManager().createFunction(name, at, body, SourceType.USER_DEFINED);
	}

	private int context(String name, Address at) {
		Register register = currentProgram.getRegister(name);
		if (register == null) return 0;
		var value = currentProgram.getProgramContext().getValue(register, at, false);
		return value == null ? 0 : value.intValue();
	}

	private List<Instruction> instructions(Function function) {
		List<Instruction> result = new ArrayList<>();
		currentProgram.getListing().getInstructions(function.getBody(), true).forEachRemaining(result::add);
		return result;
	}

	private boolean shadowed(Instruction instruction) {
		for (PcodeOp op : instruction.getPcode(false)) {
			List<Varnode> nodes = new ArrayList<>(Arrays.asList(op.getInputs()));
			if (op.getOutput() != null) nodes.add(op.getOutput());
			for (Varnode node : nodes) {
				Register register = node.isRegister() ? currentProgram.getRegister(node.getAddress(), node.getSize()) : null;
				if (register != null && register.getName().startsWith("C6000_LOAD_")) return true;
			}
		}
		return false;
	}

	private BytesPcodeExecutorState initial(JsonObject row, JsonObject initial) {
		var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
		for (Register register : language.getRegisters()) {
			if (!register.isProcessorContext() && register.getMinimumByteSize() == 4) {
				state.setVar(register, arithmetic.fromConst(0, 4));
			}
		}
		Map<String, Long> registers = new java.util.LinkedHashMap<>(Map.of("A5", OLD, "A6", 0x66666666L,
			"A8", 0x88888888L, "A9", 0x99999999L, "A4", 0x8000L, "B4", 0x8000L, "B3", 0x9000L));
		for (var entry : initial.entrySet()) registers.put(entry.getKey(), entry.getValue().getAsLong());
		registers.forEach((name, value) -> state.setVar(currentProgram.getRegister(name), arithmetic.fromConst(value, 4)));
		ByteOrder order = currentProgram.getMemory().isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
		ByteBuffer memory = ByteBuffer.allocate(16).order(order);
		switch (row.get("memory").getAsString()) {
			case "byte" -> memory.put(0, (byte) 0x80);
			case "half" -> memory.putShort(0, (short) 0x8001);
			case "double" -> memory.putLong(0, 0x1122334455667788L);
			default -> memory.putInt(0, 0x12345678);
		}
		state.setVar(address(0x8000), 16, false, memory.array());
		return state;
	}

	private long value(BytesPcodeExecutorState state, String register) {
		return arithmetic.toLong(state.getVar(currentProgram.getRegister(register),
			PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT) & 0xFFFFFFFFL;
	}

	/** Runs listing p-code, packet by packet in address order, up to the return. */
	private BytesPcodeExecutorState run(Function function, JsonObject row, JsonObject initial) {
		var state = initial(row, initial);
		var library = PcodeUseropLibrary.<byte[]>nil();
		var executor = new PcodeExecutor<byte[]>(language, arithmetic, state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
		for (Instruction instruction : instructions(function)) {
			var flow = instruction.getFlowType();
			if (flow.isJump() || flow.isCall() || flow.isTerminal()) break;
			var frame = executor.begin(new PcodeProgram(language, Arrays.asList(instruction.getPcode(false)),
				library.getSymbols(language)) {});
			int steps = 0;
			while (!frame.isFinished() && steps++ < 10000) executor.step(frame, library);
			if (!frame.isFinished()) throw new AssertionError("p-code step bound at " + instruction.getAddress());
		}
		return state;
	}

	private String decompile(Function function) {
		var decompiler = new DecompInterface();
		decompiler.setOptions(new DecompileOptions());
		decompiler.openProgram(currentProgram);
		try {
			var result = decompiler.decompileFunction(function, 60, monitor);
			if (result == null || !result.decompileCompleted()) return null;
			return result.getDecompiledFunction().getC().replaceAll("\\s+", " ").trim();
		}
		finally {
			decompiler.dispose();
		}
	}

	private void expect(boolean condition, String name, String message) {
		if (!condition) failures.add(name + ": " + message);
	}

	private int check(JsonObject row) {
		String name = row.get("name").getAsString();
		String kind = row.get("kind").getAsString();
		Function function = currentProgram.getFunctionManager().getFunctionAt(address(row.get("entry").getAsLong()));
		if (function == null) {
			failures.add(name + ": missing function");
			return 0;
		}
		List<Instruction> body = instructions(function);
		String warning = body.stream().map(i -> currentProgram.getBookmarkManager()
			.getBookmark(i.getAddress(), BookmarkType.WARNING, WARNING)).filter(b -> b != null)
			.map(b -> b.getComment()).findFirst().orElse(null);
		boolean warned = warning != null;
		long shadows = body.stream().filter(i -> context("c_load_mode", i.getAddress()) == 1).count();
		long commits = body.stream().filter(i -> context("c_load_mode", i.getAddress()) == 2).count();
		boolean lifted = body.stream().anyMatch(this::shadowed);
		switch (kind) {
			case "exact" -> {
				expect(!warned, name, "exact deferral still carries the inexact-pipeline warning: " + warning);
				expect(shadows == 1 && commits == 1 && lifted, name, "expected one shadow and one commit, saw " +
					shadows + "/" + commits + " lifted=" + lifted);
				String c = decompile(function);
				println("NATIVE_LOAD_LATENCY_C " + name + " " + c);
				expect(c != null && !c.contains("C6000_LOAD"), name, "decompiled C leaks the shadow or failed: " + c);
			}
			case "refused" -> {
				expect(warned, name, "a refusal must keep the inexact-pipeline warning");
				expect(shadows == 0 && commits == 0 && !lifted, name, "a refusal must keep native lifting, saw " +
					shadows + "/" + commits + " lifted=" + lifted);
			}
			default -> {
				expect(!warned && shadows == 0 && commits == 0 && !lifted, name, "a function without the hazard changed");
				String c = decompile(function);
				println("NATIVE_LOAD_LATENCY_C " + name + " " + c);
				String base = BASE_C.get(name);
				expect(c != null && c.equals(base), name, "C differs from 7015913: " + c);
			}
		}
		int runs = 0;
		for (var element : row.getAsJsonArray("runs")) {
			JsonObject run = element.getAsJsonObject();
			var state = run(function, row, run.getAsJsonObject("initial"));
			for (var entry : run.getAsJsonObject("expected").entrySet()) {
				long actual = value(state, entry.getKey());
				long wanted = entry.getValue().getAsLong() & 0xFFFFFFFFL;
				expect(actual == wanted, name, run.getAsJsonObject("initial") + " " + entry.getKey() +
					" hardware=0x" + Long.toHexString(wanted) + " lifted=0x" + Long.toHexString(actual));
			}
			runs++;
		}
		return runs;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		JsonArray cases = JsonParser.parseString(Files.readString(Path.of(args[args.length - 1]))).getAsJsonArray();
		if (args.length == 2 && args[0].equals("prepare")) {
			prepare(cases);
			return;
		}
		language = (SleighLanguage) currentProgram.getLanguage();
		arithmetic = BytesPcodeArithmetic.forLanguage(language);
		int runs = 0;
		Map<String, Integer> kinds = new java.util.TreeMap<>();
		for (var element : cases) {
			JsonObject row = element.getAsJsonObject();
			int before = failures.size();
			runs += check(row);
			kinds.merge(row.get("kind").getAsString(), 1, Integer::sum);
			println("NATIVE_LOAD_LATENCY_CASE " + row.get("name").getAsString() + " " +
				(failures.size() == before ? "PASS" : "FAIL"));
		}
		if (!failures.isEmpty()) throw new AssertionError(failures.size() + " failures:\n" + String.join("\n", failures));
		if (cases.size() != 20 || kinds.getOrDefault("exact", 0) != 12 || kinds.getOrDefault("refused", 0) != 6 ||
				runs != 15) {
			throw new AssertionError("incomplete coverage: " + kinds + " runs=" + runs);
		}
		println("C6000_NATIVE_LOAD_LATENCY_OK cases=" + cases.size() + " exact=" + kinds.get("exact") +
			" refused=" + kinds.get("refused") + " native=" + kinds.get("native") + " runs=" + runs);
	}
}
