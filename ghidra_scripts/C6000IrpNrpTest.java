// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check B IRP / B NRP decode and one emulated step against irp-nrp.py cases. Usage: <cases.tsv>.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000IrpNrpTest extends GhidraScript {
	private static final long IRP = 0x2000, NRP = 0x3000;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) throw new IllegalArgumentException("expected cases.tsv path");
		int checked = 0;
		try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
			String row;
			while ((row = rows.readLine()) != null) {
				String[] f = row.split("\\t");
				long offset = 0x1000L + 32L * Integer.parseInt(f[0]);
				Address address = toAddr(offset);
				new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
				Instruction insn = getInstructionAt(address);
				if (insn == null || !insn.toString().endsWith(" " + f[1])) {
					throw new AssertionError(f[0] + ": decoded as " + insn);
				}
				EmulatorHelper emulator = new EmulatorHelper(currentProgram);
				try {
					emulator.writeRegister("IRP", IRP);
					emulator.writeRegister("NRP", NRP);
					for (String kv : pairs(f[2])) {
						String[] p = kv.split("=");
						emulator.writeRegister(p[0], Long.parseUnsignedLong(p[1], 16));
					}
					emulator.getEmulator().setExecuteAddress(offset);
					if (!emulator.step(monitor)) {
						throw new AssertionError(f[0] + ": " + emulator.getLastError());
					}
					for (String kv : pairs(f[3])) {
						String[] p = kv.split("=");
						long got = p[0].equals("pc") ? emulator.getExecutionAddress().getOffset()
								: emulator.readRegister(p[0]).longValue();
						long want = !p[0].equals("pc") ? Long.parseUnsignedLong(p[1], 16)
								: p[1].equals("irp") ? IRP : p[1].equals("nrp") ? NRP : offset + 4;
						if (got != want) {
							throw new AssertionError(f[0] + ": " + p[0] + "=0x" + Long.toHexString(got) +
								" expected 0x" + Long.toHexString(want));
						}
					}
				}
				finally {
					emulator.dispose();
				}
				checked++;
			}
		}
		println("C6000_IRP_NRP_OK cases=" + checked);
	}

	private static String[] pairs(String field) {
		return field.equals("-") ? new String[0] : field.split(",");
	}
}
