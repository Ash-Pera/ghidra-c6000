// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Usage: <pipeline-float cases.tsv>. SPRUFE8B 4.2 E4 writeback / MPYSP RMODE.
import java.nio.file.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class C6000PipelineFloatTest extends GhidraScript {
    long hex(String text) { return Long.parseUnsignedLong(text,16); }
    protected void run() throws Exception {
        c6000.C6000PacketContext.prime(currentProgram, monitor);
        var arithmetic = BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());
        var inspect = PcodeExecutorStatePiece.Reason.INSPECT;
        int checked = 0;
        for (String row : Files.readAllLines(Paths.get(getScriptArgs()[0]))) {
            var fields = row.split("\t");
            var entry = toAddr(0x1000L + 64L * Integer.parseInt(fields[0]));
            var function = currentProgram.getFunctionManager().createFunction("float_"+fields[0],
                entry, new AddressSet(entry, entry.add(63)), SourceType.USER_DEFINED);
            var result = new c6000.C6000PipelineCompiler(currentProgram, function).compile();
            var state = new BytesPcodeExecutorState(currentProgram.getLanguage(), PcodeStateCallbacks.NONE);
            for (var register : currentProgram.getLanguage().getRegisters()) {
                if (!register.isProcessorContext() && register.getMinimumByteSize() == 4)
                    state.setVar(register, arithmetic.fromConst(0,4));
            }
            state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000,4));
            state.setVar(currentProgram.getRegister(fields[3]), arithmetic.fromConst(0x55,4));
            state.setVar(currentProgram.getRegister(fields[1]), arithmetic.fromConst(hex(fields[6]),4));
            state.setVar(currentProgram.getRegister(fields[2]), arithmetic.fromConst(hex(fields[7]),4));
            state.setVar(currentProgram.getRegister("FMCR"), arithmetic.fromConst(hex(fields[9]),4));
            var library = PcodeUseropLibrary.<byte[]>nil();
            var executor = new PcodeExecutor<byte[]>((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage()), state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
            var frame = executor.begin(new ghidra.pcode.exec.PcodeProgram((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), Arrays.asList(result.code()), library.getSymbols(
                (ghidra.app.plugin.processors.sleigh.SleighLanguage)currentProgram.getLanguage())) {});
            int steps = 0;
            while (!frame.isFinished() && steps++ < 100000) executor.step(frame, library);
            if (!frame.isFinished()) throw new AssertionError("Step bound " + fields[0]);
            long old = fields[3].equals(fields[1]) ? hex(fields[6]) : 0x55;
            Map<String,Long> expected = Map.of(fields[3],hex(fields[8]), fields[4],old,
                fields[5],hex(fields[8]), "FMCR",hex(fields[10]), "PC",0x9000L);
            for (var item : expected.entrySet()) {
                long actual = arithmetic.toLong(state.getVar(currentProgram.getRegister(item.getKey()),inspect),
                    PcodeArithmetic.Purpose.INSPECT);
                if (actual != item.getValue()) throw new AssertionError("case " + fields[0] + " " +
                    item.getKey() + "=" + Long.toHexString(actual) + " expected=" + Long.toHexString(item.getValue()));
            }
            checked++;
        }
        if (checked != 120) throw new AssertionError("Incomplete float corpus " + checked);
        println("C6000_PIPELINE_FLOAT_OK cases="+checked);
    }
}
