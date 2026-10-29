// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B pp.145-146: ANDN reads and writes in E1 on .L/.S/.D.
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;

public class C6000PipelineAndnTest extends GhidraScript {
    private BytesPcodeArithmetic arithmetic;

    private BytesPcodeExecutorState initialized(JsonObject row) {
        var state = new BytesPcodeExecutorState(currentProgram.getLanguage(), PcodeStateCallbacks.NONE);
        for (var register : currentProgram.getLanguage().getRegisters()) {
            if (!register.isProcessorContext() && register.getMinimumByteSize() == 4)
                state.setVar(register, arithmetic.fromConst(0, 4));
        }
        state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
        state.setVar(currentProgram.getRegister("AMR"), arithmetic.fromConst(0x12345678, 4));
        state.setVar(currentProgram.getRegister("CSR"), arithmetic.fromConst(0x2468, 4));
        for (var item : row.getAsJsonObject("input").entrySet())
            state.setVar(currentProgram.getRegister(item.getKey()), arithmetic.fromConst(item.getValue().getAsLong(), 4));
        return state;
    }

    private void execute(PcodeOp[] code, BytesPcodeExecutorState state, String name) {
        var executor = new PcodeExecutor<byte[]>((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage()), state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
        var library = PcodeUseropLibrary.<byte[]>nil();
        var frame = executor.begin(new ghidra.pcode.exec.PcodeProgram((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), Arrays.asList(code), library.getSymbols(
            (ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage())) {});
        int steps = 0;
        while (!frame.isFinished() && steps++ < 100000) executor.step(frame, library);
        if (!frame.isFinished()) throw new AssertionError("Step bound: " + name);
    }

    private long value(BytesPcodeExecutorState state, String register) {
        return arithmetic.toLong(state.getVar(currentProgram.getRegister(register),
            PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT);
    }

    @Override
    protected void run() throws Exception {
        c6000.C6000PacketContext.prime(currentProgram, monitor);
        arithmetic = BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());
        var records = new JsonArray();
        int count = 0, rawCount = 0;
        for (var element : JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray()) {
            var row = element.getAsJsonObject();
            String name = row.get("name").getAsString();
            var at = toAddr(row.get("entry").getAsLong());
            var function = currentProgram.getFunctionManager().createFunction(name, at,
                new AddressSet(at, at.add(0x7f)), SourceType.USER_DEFINED);
            if (!new DisassembleCommand(at, new AddressSet(at, at.add(3)), false).applyTo(currentProgram, monitor))
                throw new AssertionError("Cannot decode " + name);
            Instruction instruction = getInstructionAt(at);
            if (instruction == null || !instruction.getMnemonicString().contains("ANDN."))
                throw new AssertionError("Unexpected decode: " + instruction);
            row.addProperty("decoded", instruction.toString());

            if (row.has("refused")) {
                boolean refused = false;
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
                if (BigInteger.ONE.equals(context)) throw new AssertionError("Refusal mutated entry context");
                count++;
                records.add(row);
                continue;
            }

            var rawState = initialized(row);
            execute(instruction.getPcode(false), rawState, name + " raw");
            String rawDestination = row.get("raw_destination").getAsString();
            long rawActual = value(rawState, rawDestination);
            if (rawActual != row.get("raw_expected").getAsLong())
                throw new AssertionError(name + " raw " + rawDestination + "=" + Long.toHexString(rawActual));
            row.addProperty("raw_actual", rawActual);
            rawCount++;

            var result = new c6000.C6000PipelineCompiler(currentProgram, function).compile();
            var state = initialized(row);
            execute(result.code(), state, name);
            var actual = new JsonObject();
            for (var expected : row.getAsJsonObject("expected").entrySet()) {
                long observed = value(state, expected.getKey());
                if (observed != expected.getValue().getAsLong())
                    throw new AssertionError(name + " " + expected.getKey() + "=" +
                        Long.toHexString(observed) + " expected=" + Long.toHexString(expected.getValue().getAsLong()));
                actual.addProperty(expected.getKey(), observed);
            }
            row.add("actual", actual);
            row.addProperty("states", result.states());
            row.addProperty("operations", result.code().length);
            records.add(row);
            println("ANDN_CASE " + name);
            count++;
        }
        Files.writeString(Paths.get(getScriptArgs()[0] + ".results.json"),
            new GsonBuilder().setPrettyPrinting().create().toJson(records));
        if(count != 234 || rawCount != 228) throw new AssertionError("Incomplete ANDN matrix");
        println("C6000_PIPELINE_ANDN_OK cases=" + count + " raw=" + rawCount);
    }
}
