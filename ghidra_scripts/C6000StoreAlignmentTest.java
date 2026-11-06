// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Execute STB/STH/STW/STDW through misaligned addresses: the hardware ignores the low address bits.

import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000StoreAlignmentTest extends GhidraScript {
    private static long hex(String value) { return Long.parseUnsignedLong(value, 16); }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("expected cases.tsv path");
        int checked = 0;
        try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
            String row;
            while ((row = rows.readLine()) != null) {
                String[] f = row.split("\t");
                Address pc = toAddr(0x1000L + 32L * Integer.parseInt(f[0]));
                Instruction insn = currentProgram.getListing().getInstructionAt(pc);
                if (insn == null) {
                    new DisassembleCommand(pc, null, false).applyTo(currentProgram, monitor);
                    insn = currentProgram.getListing().getInstructionAt(pc);
                }
                if (insn == null || !insn.getMnemonicString().startsWith(f[1] + ".")) throw new AssertionError(f[0] + ": decoded as " + insn);
                int width = Integer.parseInt(f[6]);
                long effective = hex(f[7]);
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    for (long a = 0x1300; a < 0x1360; a++) emulator.writeMemoryValue(toAddr(a), 1, 0xee);
                    emulator.writeRegister(f[2], hex(f[3]));
                    emulator.writeRegister(f[4], new BigInteger(f[5], 16));
                    emulator.getEmulator().setExecuteAddress(pc.getOffset());
                    if (!emulator.step(monitor)) throw new AssertionError(f[0] + ": " + emulator.getLastError());
                    for (long a = 0x1300; a < 0x1360; a++) {
                        int actual = emulator.readMemoryByte(toAddr(a)) & 0xff;
                        long i = a - effective;
                        int expected = i >= 0 && i < width ? Integer.parseInt(f[8].substring((int) (2 * i), (int) (2 * i + 2)), 16) : 0xee;
                        if (actual != expected) throw new AssertionError(f[0] + " " + f[1] + ": byte at 0x" + Long.toHexString(a) + " =0x" + Integer.toHexString(actual) + " expected=0x" + Integer.toHexString(expected));
                    }
                    long base = emulator.readRegister(f[2]).longValue() & 0xffffffffL;
                    if (base != hex(f[9])) throw new AssertionError(f[0] + ": base=0x" + Long.toHexString(base) + " expected=0x" + f[9]);
                } finally {
                    emulator.dispose();
                }
                checked++;
            }
        }
        println("C6000_STORE_ALIGNMENT_OK cases=" + checked);
    }
}
