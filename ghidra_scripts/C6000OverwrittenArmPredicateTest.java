// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Verify nested-return effects and refused predicate/window variants in the overwritten-arm fixture.

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class C6000OverwrittenArmPredicateTest extends GhidraScript {
	private static final String[] REFUSED = {
		"bad_unimplied", "bad_later_write", "bad_non_nop_tail", "bad_first_packet", "bad_extra_jump", "bad_peer_link"
	};

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 2 && getScriptArgs()[0].equals("prepare")) {
			prepare(Path.of(getScriptArgs()[1]));
			return;
		}
		if (getScriptArgs().length != 1) throw new AssertionError("expected cases.tsv");
		Map<String, long[]> cases = readCases(Path.of(getScriptArgs()[0]));
		long[] main = requireCase(cases, "overwritten_arm");
		Function f = getFunctionAt(toAddr(main[0]));
		if (f == null) throw new AssertionError("missing overwritten-arm function");
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null)
				throw new AssertionError("decompile failed: " + (result == null ? "null" : result.getErrorMessage()));
			String c = result.getDecompiledFunction().getC();
			println(c);
			assertPathEffects(c);
		}
		finally {
			decompiler.dispose();
		}
		for (String name : REFUSED) {
			long[] range = requireCase(cases, name);
			assertRefused(name, range[0], range[1]);
		}
		println("C6000_OVERWRITTEN_ARM_PREDICATE_OK");
	}

	private void prepare(Path manifest) throws Exception {
		Map<String, long[]> cases = readCases(manifest);
		C6000PacketContext.prime(currentProgram, monitor);
		for (var entry : cases.entrySet()) {
			long[] range = entry.getValue();
			var address = toAddr(range[0]);
			currentProgram.getSymbolTable().addExternalEntryPoint(address);
			disassemble(address);
			String name = entry.getKey().equals("overwritten_arm") ? "pend" : entry.getKey();
			Function f = createFunction(address, name);
			if (f == null) throw new AssertionError("could not create fixture function " + name);
		}
	}

	private Map<String, long[]> readCases(Path manifest) throws Exception {
		Map<String, long[]> cases = new LinkedHashMap<>();
		for (String line : Files.readAllLines(manifest)) {
			String[] fields = line.split("\t");
			if (fields.length != 3) throw new AssertionError("invalid fixture case: " + line);
			long start = Long.parseUnsignedLong(fields[1], 16);
			long end = Long.parseUnsignedLong(fields[2], 16);
			if (end <= start || cases.put(fields[0], new long[] { start, end }) != null)
				throw new AssertionError("invalid fixture range: " + line);
		}
		return cases;
	}

	private long[] requireCase(Map<String, long[]> cases, String name) {
		long[] range = cases.get(name);
		if (range == null) throw new AssertionError("missing fixture case " + name);
		return range;
	}

	// Each path's effects: p[4] != 0 decrements and stores p[4] and returns 1; return 0 stores nothing; else g2 = 2, return 9.
	private void assertPathEffects(String c) {
		String p4 = p4LoadRegister(c);
		check(p4 != null, "no p[4] load");
		int one = c.indexOf("return 1;"), zero = c.indexOf("return 0;"), nine = c.indexOf("return 9;");
		check(one >= 0 && zero > one && nine > zero, "returns missing or out of order");
		int oneOpen = c.lastIndexOf('{', one);
		check(lineAt(c, oneOpen).equals("if (" + p4 + " != 0) {"), "return 1 not guarded by p[4] != 0");
		String oneBody = c.substring(oneOpen + 1, one);
		Matcher decrement = Pattern.compile("\\b(\\w+) = " + Pattern.quote(p4) + " \\+ -1;").matcher(c);
		check(decrement.find() && decrement.start() < oneOpen, "no p[4] - 1");
		check(lineAt(c, c.lastIndexOf('{', decrement.start())).equals("if (" + p4 + " != 0) {"),
			"p[4] - 1 not guarded by p[4] != 0");
		check(Pattern.compile("\\*\\(int \\*\\)\\([^\\n]*param_1 \\+ 0x10[^\\n]*\\) = " +
			Pattern.quote(decrement.group(1)) + ";").matcher(oneBody).find(), "return 1 path does not store p[4] - 1");
		check(!oneBody.contains("0x108"), "return 1 path stores g2");
		int oneClose = c.indexOf('}', one);
		int zeroOpen = c.lastIndexOf('{', zero);
		check(zeroOpen > oneClose && c.substring(zeroOpen + 1, zero).isBlank(), "return 0 path has effects or nests");
		String tail = c.substring(c.indexOf('}', zero) + 1, nine);
		check(!tail.contains("return") && !tail.contains("param_1"), "return 9 path has another exit or p[4] store");
		check(Pattern.compile("\\([^\\n]*0x108\\) = 2;").matcher(tail).find(), "return 9 path does not store g2 = 2");
		check(c.substring(nine + "return 9;".length()).trim().equals("}"), "return 9 is not the final exit");
	}

	private static String lineAt(String c, int at) {
		if (at < 0) return "";
		int start = c.lastIndexOf('\n', at) + 1, end = c.indexOf('\n', at);
		return c.substring(start, end < 0 ? c.length() : end).trim();
	}

	private static void check(boolean ok, String message) {
		if (!ok) throw new AssertionError("wrong nested return effects: " + message);
	}

	private String p4LoadRegister(String c) {
		Matcher load = Pattern.compile("(?m)^\\s*(\\w+) = \\*\\(int \\*\\)\\([^\\n]*param_1 \\+ 0x10[^\\n]*\\);$").matcher(c);
		return load.find() ? load.group(1) : null;
	}

	private void assertRefused(String name, long start, long end) {
		var inert = currentProgram.getRegister("c_inert");
		var carry = currentProgram.getRegister("c_carry");
		var listing = currentProgram.getListing();
		for (long offset = start; offset < end; offset += 4) {
			var address = toAddr(offset);
			var instruction = listing.getInstructionAt(address);
			var destination = instruction == null ? null : instruction.getRegister(0);
			boolean returnBranch = destination != null && destination.getName().equals("B3");
			if (set(carry, address) || returnBranch && set(inert, address))
				throw new AssertionError("bad nested carry applied: " + name + " at " + address);
		}
	}

	private boolean set(ghidra.program.model.lang.Register register, ghidra.program.model.address.Address address) {
		var value = currentProgram.getProgramContext().getValue(register, address, false);
		return value != null && value.signum() != 0;
	}
}
