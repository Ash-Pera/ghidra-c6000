// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Exact arithmetic, alias and predicate oracle: exact-fp-selection.py cases.tsv.
import java.nio.file.Files;
import java.nio.file.Paths;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.pcode.PcodeOp;

public class C6000ExactFloatSelectionTest extends GhidraScript {
    private long hex(String s) { return Long.parseUnsignedLong(s, 16); }
    protected void run() throws Exception {
        int checked = 0;
        for (String row : Files.readAllLines(Paths.get(getScriptArgs()[0]))) {
            String[] f = row.split("\\t");
            long offset = 0x1000L + 32L * Integer.parseInt(f[0]);
            var address = toAddr(offset);
            new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
            var insn = currentProgram.getListing().getInstructionAt(address);
            if (insn == null || !insn.getMnemonicString().endsWith(f[1])) {
                throw new AssertionError(f[0] + ": wrong instruction " + insn);
            }
            int branches = 0;
            for (var op : insn.getPcode()) {
                if (op.getOpcode() == PcodeOp.CALLOTHER) {
                    throw new AssertionError(f[0] + ": opaque arithmetic");
                }
                if (op.getOpcode() == PcodeOp.BRANCH || op.getOpcode() == PcodeOp.CBRANCH) branches++;
            }
            // Only the architectural predicate may add a p-code branch.
            if (branches > 1) throw new AssertionError(f[0] + ": internal branches=" + branches);
            var emu = new EmulatorHelper(currentProgram);
            try {
                emu.writeRegister(f[4], 0x5a5a5a5aL);
                emu.writeRegister(f[2], hex(f[5]));
                emu.writeRegister(f[3], hex(f[6]));
                emu.writeRegister("A0", Long.parseLong(f[11]));
                emu.writeRegister(f[8], hex(f[9]));
                String otherControl = f[8].equals("FMCR") ? "FADCR" : "FMCR";
                emu.writeRegister(otherControl, 0x06250625L);
                emu.getEmulator().setExecuteAddress(offset);
                if (!emu.step(monitor)) throw new AssertionError(emu.getLastError());
                if ((emu.readRegister(f[4]).longValue() & 0xffffffffL) != hex(f[7]) ||
                    emu.readRegister(f[8]).longValue() != hex(f[10]) ||
                    emu.readRegister(otherControl).longValue() != 0x06250625L) {
                    throw new AssertionError("case " + row + " actual=" +
                        emu.readRegister(f[4]).toString(16) + "/" + emu.readRegister(f[8]).toString(16));
                }
                for (int port = 2; port <= 3; port++) {
                    if (!f[port].equals(f[4]) && emu.readRegister(f[port]).longValue() != hex(f[port+3])) {
                        throw new AssertionError(f[0] + ": source clobbered");
                    }
                }
            } finally { emu.dispose(); }
            checked++;
        }
        println("C6000_EXACT_FLOAT_SELECTION_OK cases=" + checked);
    }
}
