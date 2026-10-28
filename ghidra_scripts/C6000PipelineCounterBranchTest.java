// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Exact BDEC/BPOS E1 effects and five-delay transfers, SPRUFE8B pp159-160/170-171.
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;

public class C6000PipelineCounterBranchTest extends GhidraScript {
    private BytesPcodeArithmetic arithmetic;

    private BytesPcodeExecutorState initialized(JsonObject row) {
        var state = new BytesPcodeExecutorState(currentProgram.getLanguage(), PcodeStateCallbacks.NONE);
        for (var register : currentProgram.getLanguage().getRegisters()) {
            if (!register.isProcessorContext() && register.getMinimumByteSize() == 4)
                state.setVar(register, arithmetic.fromConst(0, 4));
        }
        state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
        for (var item : row.getAsJsonObject("input").entrySet())
            state.setVar(currentProgram.getRegister(item.getKey()), arithmetic.fromConst(item.getValue().getAsLong(), 4));
        return state;
    }

    private void execute(PcodeOp[] code, BytesPcodeExecutorState state, String name) {
        var executor = new PcodeExecutor<byte[]>((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage()), state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
        var library = PcodeUseropLibrary.<byte[]>nil();
        var frame = executor.begin(new ghidra.pcode.exec.PcodeProgram((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), Arrays.asList(code), library.getSymbols(
            (ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage())) {});
        // The fixture has at most four visits to its backward-loop branch;
        // every other case is acyclic. No operation can execute more than four times.
        int bound = code.length * 4, steps = 0;
        while (!frame.isFinished() && steps++ < bound) executor.step(frame, library);
        if (!frame.isFinished()) throw new AssertionError("Fixture visit bound: " + name);
    }

    @Override
    protected void run() throws Exception {
        c6000.C6000PacketContext.prime(currentProgram, monitor);
        arithmetic = BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());
        var records = new JsonArray();
        int count = 0, refusedCount = 0;
        for (var element : JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray()) {
            var row = element.getAsJsonObject();
            String name = row.get("name").getAsString();
            var at = toAddr(row.get("entry").getAsLong());
            var function = currentProgram.getFunctionManager().createFunction(name, at,
                new AddressSet(at, at.add(0x1ff)), SourceType.USER_DEFINED);
            var branchAt = at.add(row.has("branch_offset") ? row.get("branch_offset").getAsLong() : 0);
            if (!new DisassembleCommand(branchAt, new AddressSet(branchAt, branchAt.add(3)), false).applyTo(currentProgram, monitor))
                throw new AssertionError("Cannot decode " + name);
            var instruction = getInstructionAt(branchAt);
            if (instruction == null || !instruction.getMnemonicString().contains(row.get("operation").getAsString()))
                throw new AssertionError("Wrong decode: " + instruction);
            row.addProperty("decoded", instruction.toString());
            if (row.has("refused")) {
                boolean refused = false;
                byte[] before = getBytes(at, 4);
                try {
                    c6000.C6000PipelineSchedules.enable(currentProgram, function,
                        "Synthetic drained entry", Set.of(), monitor);
                } catch (IllegalArgumentException error) {
                    if (!error.getMessage().contains(row.get("refused").getAsString())) throw error;
                    refused = true;
                }
                if (!refused) throw new AssertionError("Invalid schedule accepted: " + name);
                var context = currentProgram.getProgramContext().getValue(
                    currentProgram.getRegister("c_schedule_entry"), at, false);
                if (BigInteger.ONE.equals(context) || !Arrays.equals(before, getBytes(at, 4)))
                    throw new AssertionError("Refusal modified entry: " + name);
                count++;
                refusedCount++;
                records.add(row);
                continue;
            }
            var result = new c6000.C6000PipelineCompiler(currentProgram, function).compile();
            long subtractions = Arrays.stream(result.code()).filter(op -> op.getOpcode() == PcodeOp.INT_SUB).count();
            if (row.has("expected_subtractions") && subtractions != row.get("expected_subtractions").getAsLong())
                throw new AssertionError("Counter arithmetic duplicated: " + name + " subtractions=" + subtractions);
            var state = initialized(row);
            execute(result.code(), state, name);
            var actual = new JsonObject();
            for (var expected : row.getAsJsonObject("expected").entrySet()) {
                long value = arithmetic.toLong(state.getVar(currentProgram.getRegister(expected.getKey()),
                    PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT) & 0xffffffffL;
                if (value != expected.getValue().getAsLong())
                    throw new AssertionError(name + " " + expected.getKey() + " got0x" + Long.toHexString(value) +
                        " expected0x" + Long.toHexString(expected.getValue().getAsLong()));
                actual.addProperty(expected.getKey(), value);
            }
            row.add("actual", actual);
            row.addProperty("states", result.states());
            row.addProperty("operations", result.code().length);
            row.addProperty("subtractions", subtractions);
            records.add(row);
            println("COUNTER_BRANCH_CASE " + name);
            count++;
        }
        Files.writeString(Paths.get(getScriptArgs()[0] + ".results.json"),
            new GsonBuilder().setPrettyPrinting().create().toJson(records));
        println("C6000_PIPELINE_COUNTER_BRANCH_OK cases=" + count + " refused=" + refusedCount);
    }
}
