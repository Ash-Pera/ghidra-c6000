// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B 2.8.3, 3.9.2, 4.2.5-4.2.6 and Figures C-8..C-15.
// Usage: C6000CompactMemoryTest.java cases.json
import java.nio.file.*;
import java.util.*;
import com.google.gson.Gson;
import c6000.C6000PacketContext;
import c6000.C6000PipelineCompiler;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;

public class C6000CompactMemoryTest extends GhidraScript {
    static class Case {
        String name, assembly, memory;
        Map<String, Long> input, raw_expected, scheduled_expected;
        boolean alias;
    }
    static final long ARENA = 0x20000, RETURN = 0x9000;
    private SleighLanguage language;
    private BytesPcodeArithmetic arithmetic;

    private long seed(int side, int register) {
        return 0x12000000L + side * 0x01000000L + register * 0x10101L;
    }

    private BytesPcodeExecutorState initialized(Case c) {
        var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
        state.setVar(currentProgram.getAddressFactory().getRegisterSpace().getAddress(0),
            0x2100, false, new byte[0x2100]);
        for (int side = 0; side < 2; side++) for (int r = 0; r < 32; r++) {
            String name = (side == 0 ? "A" : "B") + r;
            state.setVar(currentProgram.getRegister(name), arithmetic.fromConst(seed(side, r), 4));
        }
        for (var input : c.input.entrySet()) state.setVar(currentProgram.getRegister(input.getKey()),
            arithmetic.fromConst(input.getValue(), 4));
        byte[] memory = new byte[512];
        for (int i = 0; i < memory.length; i++) memory[i] = (byte)(0x81 + 37 * i);
        state.setVar(toAddr(ARENA), memory.length, false, memory);
        return state;
    }

    private void execute(Case c, PcodeOp[] operations, boolean scheduled) {
        var state = initialized(c);
        var library = PcodeUseropLibrary.<byte[]>nil();
        var executor = new PcodeExecutor<byte[]>(language, arithmetic, state,
            PcodeExecutorStatePiece.Reason.EXECUTE_READ);
        var code = new PcodeProgram(language, Arrays.asList(operations), library.getSymbols(language)) {};
        var frame = executor.begin(code);
        int steps = 0;
        while (!frame.isFinished() && steps++ < 200000) executor.step(frame, library);
        if (!frame.isFinished()) throw new AssertionError(c.name + ": execution bound");
        String label = c.name + (scheduled ? " scheduled" : " raw");
        var expected = scheduled ? c.scheduled_expected : c.raw_expected;
        var reason = PcodeExecutorStatePiece.Reason.INSPECT;
        for (int side = 0; side < 2; side++) for (int r = 0; r < 32; r++) {
            String name = (side == 0 ? "A" : "B") + r;
            equal(expected.getOrDefault(name, seed(side, r)), state, name, label);
        }
        for (String name : List.of("AMR", "CSR")) equal(expected.get(name), state, name, label);
        if (scheduled) equal(RETURN, state, "PC", label);
        byte[] actual = state.getVar(toAddr(ARENA), 512, false, reason);
        byte[] wanted = HexFormat.of().parseHex(c.memory);
        if (!Arrays.equals(actual, wanted)) {
            int mismatch = Arrays.mismatch(actual, wanted);
            throw new AssertionError(label + " memory at 0x" + Long.toHexString(ARENA + mismatch) +
                " expected=0x" + Integer.toHexString(wanted[mismatch] & 255) +
                " actual=0x" + Integer.toHexString(actual[mismatch] & 255));
        }
    }

    private void equal(long expected, BytesPcodeExecutorState state, String register, String label) {
        long actual = arithmetic.toLong(state.getVar(currentProgram.getRegister(register),
            PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT) & 0xffffffffL;
        if (actual != expected) throw new AssertionError(label + " " + register +
            " expected=0x" + Long.toHexString(expected) + " actual=0x" + Long.toHexString(actual));
    }

    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("expected cases.json");
        Case[] cases = new Gson().fromJson(Files.readString(Paths.get(getScriptArgs()[0])), Case[].class);
        language = (SleighLanguage) currentProgram.getLanguage();
        arithmetic = BytesPcodeArithmetic.forLanguage(language);
        C6000PacketContext.prime(currentProgram, monitor);
        int raw = 0, scheduled = 0, aliases = 0;
        for (int index = 0; index < cases.length; index++) {
            monitor.checkCancelled();
            var c = cases[index];
            var at = toAddr(0x1000L + index * 32L);
            var body = new AddressSet(at, at.add(23));
            if (!new DisassembleCommand(at, body, false).applyTo(currentProgram, monitor))
                throw new AssertionError("Cannot disassemble " + c.name);
            var instruction = getInstructionAt(at);
            if (instruction == null || instruction.getLength() != 2 ||
                !instruction.toString().replaceAll("\\s+", "").equals(c.assembly.replaceAll("\\s+", "")))
                throw new AssertionError(c.name + " decoded as " + instruction + " expected " + c.assembly);
            for (var op : instruction.getPcode(false))
                if (op.getOpcode() == PcodeOp.CALLOTHER || op.getOpcode() == PcodeOp.UNIMPLEMENTED)
                    throw new AssertionError("Opaque semantics: " + instruction);
            execute(c, instruction.getPcode(false), false); raw++;
            var function = currentProgram.getFunctionManager().createFunction("memory_" + index,
                at, body, SourceType.USER_DEFINED);
            var result = new C6000PipelineCompiler(currentProgram, function, Set.of()).compile();
            execute(c, result.code(), true); scheduled++;
            if (c.alias) aliases++;
        }
        if (cases.length != 960 || aliases != 192 || raw != 960 || scheduled != 960)
            throw new AssertionError("Incomplete compact-memory matrix");
        println("C6000_COMPACT_MEMORY_OK cases=" + cases.length + " aliases=" + aliases +
            " raw=" + raw + " scheduled=" + scheduled);
    }
}
