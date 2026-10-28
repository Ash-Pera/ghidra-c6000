// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Usage: C6000CompactMoveMemoryTest.java cases.tsv
// SPRUFE8B G-1/G-2 and C-9/C-11/C-13/C-15: explicit wide registers,
// byte offsets for NDW off/ind, scaled updates for NDW inc/dec.

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

public class C6000CompactMoveMemoryTest extends GhidraScript {
    private static final long DATA = 0x20000;

    private static long seed(int bank, int reg) {
        return 0x12000000L + bank * 0x01000000L + reg * 0x10101L;
    }

    private static int number(String reg) { return Integer.parseInt(reg.substring(1)); }
    private static int bank(String reg) { return reg.startsWith("B") ? 1 : 0; }

    private static long read64(byte[] bytes, int offset, boolean big) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            int at = big ? offset + i : offset + 7 - i;
            value = (value << 8) | (bytes[at] & 0xffL);
        }
        return value;
    }

    private static void put64(byte[] bytes, int offset, long value, boolean big) {
        for (int i = 0; i < 8; i++) {
            bytes[offset + (big ? 7 - i : i)] = (byte)(value >>> (8 * i));
        }
    }

    private static void equal(long actual, long expected, String label) {
        if ((actual & 0xffffffffL) != (expected & 0xffffffffL)) {
            throw new AssertionError(label + " got0x" + Long.toHexString(actual) +
                " expected0x" + Long.toHexString(expected));
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("expected cases.tsv");
        C6000PacketContext.prime(currentProgram, monitor);
        boolean big = currentProgram.getLanguage().isBigEndian();
        int checked = 0;
        try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
            String row;
            while ((row = rows.readLine()) != null) {
                String[] f = row.split("\t");
                Address address = toAddr(0x1000 + 32L * Integer.parseInt(f[0]));
                String kind = f[1], mnemonic = f[2], a = f[3], b = f[4];
                String baseReg = f[5], indexReg = f[6], mode = f[9];
                int count = Integer.parseInt(f[7]), na = Integer.parseInt(f[8]);
                new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
                Instruction insn = currentProgram.getListing().getInstructionAt(address);
                if (insn == null || insn.getLength() != 2 || !insn.getMnemonicString().equals(mnemonic)) {
                    throw new AssertionError(f[0] + " wrong decode: " + insn);
                }
                for (PcodeOp op : insn.getPcode()) {
                    if (op.getOpcode() == PcodeOp.CALLOTHER) {
                        throw new AssertionError(f[0] + " placeholder: " + op);
                    }
                }
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    emulator.writeRegister("AMR", 0);
                    if (kind.equals("move")) {
                        String expected = mnemonic + a + "," + b;
                        if (!insn.toString().replaceAll("\\s+", "").equals(expected)) {
                            throw new AssertionError(f[0] + " bank/display mismatch: " + insn + " expected" + expected);
                        }
                        for (int side = 0; side < 2; side++) {
                            for (int r = 0; r < 32; r++) {
                                emulator.writeRegister((side == 0 ? "A" : "B") + r, seed(side, r));
                            }
                        }
                    } else {
                        boolean unscaled = na == 1 && (mode.equals("offset") || mode.equals("indirect"));
                        String left = unscaled ? "(" : "[", right = unscaled ? ")" : "]";
                        String operand = mode.equals("indirect") ? indexReg : "0x" + Integer.toHexString(count);
                        String memory = (mode.equals("decrement") ? "*--" : "*") + baseReg +
                            (mode.equals("increment") ? "++" : "") + left + operand + right;
                        String pair = b + ":" + a;
                        String expected = mnemonic + (kind.equals("load") ? memory + "," + pair : pair + "," + memory);
                        if (!insn.toString().replaceAll("\\s+", "").equals(expected)) {
                            throw new AssertionError(f[0] + " scale/display mismatch: " + insn + " expected" + expected);
                        }
                    }
                    byte[] expectedMemory = null;
                    long expectedPair = 0, base = 0, nextBase = 0;
                    if (!kind.equals("move")) {
                        expectedMemory = new byte[256];
                        for (int i = 0; i < expectedMemory.length; i++) expectedMemory[i] = (byte)(0x60 + i);
                        base = DATA + 64 + (na == 1 ? 3 : 0);
                        long offset = (na == 1 && (mode.equals("offset") || mode.equals("indirect"))) ? count : count * 8L;
                        long access = mode.equals("decrement") ? base - offset :
                            (mode.equals("increment") ? base : base + offset);
                        nextBase = mode.equals("decrement") ? access : (mode.equals("increment") ? base + offset : base);
                        emulator.writeRegister(baseReg, base);
                        emulator.writeRegister(indexReg, count);
                        emulator.writeRegister(a, 0x55667788);
                        emulator.writeRegister(b, 0x11223344);
                        emulator.writeMemory(toAddr(DATA), expectedMemory.clone());
                        expectedPair = kind.equals("load") ? read64(expectedMemory, (int)(access - DATA), big) :
                            0x1122334455667788L;
                        if (kind.equals("store")) put64(expectedMemory, (int)(access - DATA), expectedPair, big);
                    }
                    Register context = currentProgram.getRegister("contextreg");
                    BigInteger value = currentProgram.getProgramContext().getValue(context, address, false);
                    if (value != null) emulator.setContextRegister(context, value);
                    emulator.getEmulator().setExecuteAddress(address.getOffset());
                    if (!emulator.step(monitor)) throw new AssertionError(f[0] + " emulator: " + emulator.getLastError());
                    if (kind.equals("move")) {
                        for (int side = 0; side < 2; side++) {
                            for (int r = 0; r < 32; r++) {
                                String reg = (side == 0 ? "A" : "B") + r;
                                long expected = reg.equals(b) ? seed(bank(a), number(a)) : seed(side, r);
                                equal(emulator.readRegister(reg).longValue(), expected, f[0] + " " + reg);
                            }
                        }
                    } else {
                        equal(emulator.readRegister(a).longValue(), expectedPair, f[0] + " low");
                        equal(emulator.readRegister(b).longValue(), expectedPair >>> 32, f[0] + " high");
                        equal(emulator.readRegister(baseReg).longValue(), nextBase, f[0] + " base");
                        if (!Arrays.equals(expectedMemory, emulator.readMemory(toAddr(DATA), expectedMemory.length))) {
                            throw new AssertionError(f[0] + " wrong guarded memory bytes: " + insn);
                        }
                    }
                } finally {
                    emulator.dispose();
                }
                checked++;
            }
        }
        println("C6000_COMPACT_MOVE_MEMORY_OK cases=" + checked + " endian=" + (big ? "BE" : "LE"));
    }
}
