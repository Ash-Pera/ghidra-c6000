// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check that functions ending a predicated instruction in an indirect jump or a
// call decode as listed, decompile, and keep their conditional listing flow.
// Usage: C6000PredicatedBranchTest.java <cases.tsv>  (address, expected listing text)

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;

public class C6000PredicatedBranchTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) throw new IllegalArgumentException("expected cases.tsv path");
		DecompInterface decompiler = new DecompInterface();
		int checked = 0;
		StringBuilder failures = new StringBuilder();
		try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
			decompiler.setOptions(new DecompileOptions());
			decompiler.openProgram(currentProgram);
			String row;
			while ((row = rows.readLine()) != null) {
				String[] fields = row.split("\\t");
				Address address = toAddr(Long.parseUnsignedLong(fields[0], 16));
				String label = fields[1] + " at " + address;
				if (getInstructionAt(address) == null) {
					new DisassembleCommand(address, null, true).applyTo(currentProgram, monitor);
				}
				Instruction first = getInstructionAt(address);
				if (first == null || !first.toString().equals(fields[1])) {
					failures.append(label).append(": decoded as ").append(first).append("; ");
					println("C6000_PREDICATED_BRANCH " + label + ": decoded as " + first);
					checked++;
					continue;
				}
				Function function = getFunctionAt(address);
				if (function == null) function = createFunction(address, null);
				if (function == null) throw new AssertionError("no function: " + label);
				Instruction branch = null;
				for (Instruction i : currentProgram.getListing().getInstructions(function.getBody(), true)) {
					if (i.getFlowType().isConditional()) { branch = i; break; }
				}
				if (branch == null) throw new AssertionError("no conditional flow: " + label);
				FlowType flow = branch.getFlowType();
				if (!flow.hasFallthrough() || !(flow.isComputed() || flow.isCall() || flow.isJump())) {
					throw new AssertionError("flow " + flow + ": " + label);
				}
				DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
				String error = !result.decompileCompleted() ? result.getErrorMessage().trim() :
					!result.getDecompiledFunction().getC().contains("if (") ? "no conditional in C" : null;
				println("C6000_PREDICATED_BRANCH " + label + ": " + (error == null ? "ok" : error));
				if (error != null) failures.append(label).append(": ").append(error).append("; ");
				checked++;
			}
		}
		finally {
			decompiler.dispose();
		}
		if (checked == 0) throw new AssertionError("no cases checked");
		if (failures.length() > 0) throw new AssertionError("failed: " + failures);
		println("C6000_PREDICATED_BRANCH_OK cases=" + checked);
	}
}
