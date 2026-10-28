// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check decode, operand structure and execution from compact-operands.py.
// SPRUFE8B Figures C-12/C-13/C-16/G-4 and MVK pp. 380-381.

import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.Arrays;

import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;

public class C6000CompactOperandsTest extends GhidraScript {
    private static final long DATA = 0x8000;
    private static final long SENTINEL = 0xa5b6c7d8L;
    private static final long STORE = 0x55667788L;

    private static long word(byte[] bytes, int offset, int width, boolean big) {
        long value = 0;
        for (int i = 0; i < width; i++) {
            int at = big ? offset + i : offset + width - 1 - i;
            value = (value << 8) | (bytes[at] & 0xffL);
        }
        return value;
    }

    private static void put(byte[] bytes, int offset, int width, long value, boolean big) {
        for (int i = 0; i < width; i++) {
            bytes[offset + (big ? width - 1 - i : i)] = (byte)(value >>> (8 * i));
        }
    }

    private static String high(String reg) {
        return reg.substring(0, 1) + (Integer.parseInt(reg.substring(1)) + 1);
    }

    private void equal(long actual, long expected, String label) {
        if ((actual & 0xffffffffL) != (expected & 0xffffffffL)) {
            throw new AssertionError(label + ": got0x" + Long.toHexString(actual) +
                " expected0x" + Long.toHexString(expected));
        }
    }

    private void registerOperand(Instruction insn, int index, String expected) {
        Register reg = insn.getRegister(index);
        if (reg == null || !reg.getName().equals(expected)) {
            throw new AssertionError("operand" + index + " should be" + expected + ": " + insn);
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("expected cases.tsv");
        }
        C6000PacketContext.prime(currentProgram, monitor);
        boolean big = currentProgram.getLanguage().isBigEndian();
        int checked = 0;
        try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
            String row;
            while ((row = rows.readLine()) != null) {
                String[] f = row.split("\t");
                Address address = toAddr(0x1000 + 32L * Integer.parseInt(f[0]));
                String kind = f[1], reg = f[4], ptr = f[5];
                int width = Integer.parseInt(f[2]), count = Integer.parseInt(f[6]);
                int size = Integer.parseInt(f[7]), immediate = Integer.parseInt(f[8]);
                int predicate = Integer.parseInt(f[9]);
                new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
                Instruction insn = currentProgram.getListing().getInstructionAt(address);
                if (insn == null || insn.getLength() != width || !insn.getMnemonicString().equals(f[3])) {
                    throw new AssertionError(f[0] + " wrong decode: " + insn + " expected" + f[3]);
                }
                for (PcodeOp op : insn.getPcode()) {
                    if (op.getOpcode() == PcodeOp.CALLOTHER) {
                        throw new AssertionError(f[0] + " placeholder: " + op);
                    }
                }
                String rendered = insn.toString().replaceAll("\\s+", "");
                if (kind.endsWith("-load") || kind.endsWith("-store")) {
                    boolean load = kind.endsWith("load");
                    String memory = (kind.startsWith("decrement") ? "*--" : "*") + ptr +
                        (kind.startsWith("post") ? "++" : "") + "[" +
                        (kind.startsWith("indirect") ? "A1" : "0x" + Integer.toHexString(count)) + "]";
                    String dataReg = size == 8 ? high(reg) + ":" + reg : reg;
                    String expected = f[3] + (load ? memory + "," + dataReg : dataReg + "," + memory);
                    if (!rendered.equals(expected)) {
                        throw new AssertionError("wrong memory operands: " + insn + " expected" + expected);
                    }
                } else if (kind.equals("mvk")) {
                    Scalar scalar = insn.getScalar(0);
                    if (scalar == null || scalar.getSignedValue() != immediate) {
                        throw new AssertionError("wrong signed immediate: " + insn + " expected" + immediate);
                    }
                    registerOperand(insn, 1, reg);
                } else {
                    String expected = f[3] + reg + ",1," + reg;
                    if (!rendered.equals(expected)) {
                        throw new AssertionError("missing explicit src,1,dst: " + insn);
                    }
                }

                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    emulator.writeRegister("AMR", 0);
                    emulator.writeRegister("CSR", 0);
                    emulator.writeRegister(reg, SENTINEL);
                    if (predicate >= 0) {
                        emulator.writeRegister("A0", predicate);
                    }
                    byte[] expectedMemory = null;
                    long expectedRegister = SENTINEL;
                    if (kind.startsWith("stack")) {
                        expectedMemory = new byte[128];
                        for (int i = 0; i < 32; i++) {
                            put(expectedMemory, 4 * i, 4, 0x12340000L + i, big);
                        }
                        emulator.writeRegister(ptr, DATA);
                        emulator.writeMemory(toAddr(DATA), expectedMemory.clone());
                        if (kind.equals("stack-load")) {
                            expectedRegister = 0x12340000L + count;
                        } else {
                            put(expectedMemory, count * 4, 4, SENTINEL, big);
                        }
                    } else if (kind.endsWith("-load") || kind.endsWith("-store")) {
                        expectedMemory = new byte[32];
                        for (int i = 0; i < expectedMemory.length; i++) {
                            expectedMemory[i] = (byte)(0x80 + i);
                        }
                        emulator.writeRegister(ptr, kind.startsWith("decrement") ? DATA + count * size : DATA);
                        if (kind.startsWith("indirect")) emulator.writeRegister("A1", count);
                        emulator.writeRegister(reg, STORE);
                        if (size == 8) emulator.writeRegister(high(reg), 0x11223344);
                        emulator.writeMemory(toAddr(DATA), expectedMemory.clone());
                        if (kind.equals("post-load")) {
                            expectedRegister = word(expectedMemory, 0, size, big);
                        } else {
                            int storeOffset = kind.startsWith("offset") || kind.startsWith("indirect") ? count * size : 0;
                            put(expectedMemory, storeOffset, size, size == 8 ? 0x1122334455667788L : STORE, big);
                            expectedRegister = STORE;
                        }
                    } else if (kind.equals("mvk")) {
                        expectedRegister = predicate == 0 ? SENTINEL : immediate;
                    } else {
                        expectedRegister = kind.equals("add") ? SENTINEL + 1 : SENTINEL ^ 1;
                    }
                    Register context = currentProgram.getRegister("contextreg");
                    BigInteger value = currentProgram.getProgramContext().getValue(context, address, false);
                    if (value != null) emulator.setContextRegister(context, value);
                    emulator.getEmulator().setExecuteAddress(address.getOffset());
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(f[0] + " emulator: " + emulator.getLastError());
                    }
                    equal(emulator.readRegister(reg).longValue(), expectedRegister, f[0] + " " + reg);
                    if (kind.equals("post-load") && size == 8) {
                        equal(emulator.readRegister(high(reg)).longValue(), expectedRegister >>> 32,
                            f[0] + " pair high");
                    }
                    if (expectedMemory != null) {
                        if (!Arrays.equals(expectedMemory, emulator.readMemory(toAddr(DATA), expectedMemory.length))) {
                            throw new AssertionError(f[0] + " access/update touched wrong memory bytes: " + insn + " got" + Arrays.toString(emulator.readMemory(toAddr(DATA), expectedMemory.length)) + " expected" + Arrays.toString(expectedMemory) + " pcode" + Arrays.toString(insn.getPcode()));
                        }
                        equal(emulator.readRegister(ptr).longValue(),
                            kind.startsWith("post") ? DATA + count * size : DATA, f[0] + " base");
                    }
                } finally {
                    emulator.dispose();
                }
                checked++;
            }
        }
        println("C6000_COMPACT_OPERANDS_OK cases=" + checked + " endian=" + (big ? "BE" : "LE"));
    }
}
