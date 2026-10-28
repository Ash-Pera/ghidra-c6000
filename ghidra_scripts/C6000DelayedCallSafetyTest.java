// SPDX-License-Identifier: Apache-2.0
// @category C6000
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;

public class C6000DelayedCallSafetyTest extends GhidraScript {
    protected void run() throws Exception {
        var rows = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonArray();
        c6000.C6000PacketContext.prime(currentProgram, monitor);
        for (var row : rows) {
            var item = row.getAsJsonObject();
            if (item.has("data")) createData(toAddr(item.get("data").getAsLong()), DWordDataType.dataType);
        }
        // Decode every physical instruction, including otherwise unreachable sources.
        for (long offset = 0x1000; offset < 0x4040; offset += 4) {
            var at = toAddr(offset);
            if (currentProgram.getListing().getDefinedDataContaining(at) == null)
                new DisassembleCommand(at, new AddressSet(at, at.add(3)), false).applyTo(currentProgram, monitor);
        }
        for (var row : rows) {
            var item = row.getAsJsonObject();
            if (item.has("external")) currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(item.get("external").getAsLong()));
            if (item.has("function")) {
                var at = toAddr(item.get("function").getAsLong());
                currentProgram.getFunctionManager().createFunction("alternate_entry", at, new AddressSet(at, at.add(3)), SourceType.USER_DEFINED);
            }
            if (item.has("data_reference")) {
                var ref = item.getAsJsonArray("data_reference");
                currentProgram.getReferenceManager().addMemoryReference(toAddr(ref.get(0).getAsLong()), toAddr(ref.get(1).getAsLong()), RefType.DATA, SourceType.USER_DEFINED, 0);
            }
        }
        var cls = Class.forName("c6000.C6000CallAnalyzer$Walker");
        var constructor = cls.getDeclaredConstructor(Program.class);constructor.setAccessible(true);
        var recognize = cls.getDeclaredMethod("recognize", Instruction.class);recognize.setAccessible(true);
        var walker = constructor.newInstance(currentProgram);
        long before = currentProgram.getModificationNumber();
        List<String> failures = new ArrayList<>();
        int accepted = 0;
        for (var row : rows) {
            var item = row.getAsJsonObject();
            var instruction = getInstructionAt(toAddr(item.get("site").getAsLong()));
            if (instruction == null) throw new AssertionError("Missing test instruction: " + item);
            boolean actual = recognize.invoke(walker, instruction) != null;
            boolean expected = item.get("call").getAsBoolean();
            println(item.get("name").getAsString() + " expected=" + expected + " actual=" + actual);
            if (actual != expected) failures.add(item.get("name").getAsString());
            if (expected) accepted++;
        }
        if (before != currentProgram.getModificationNumber()) throw new AssertionError("Recognition mutated the program");
        if (!failures.isEmpty()) throw new AssertionError("Wrong call verdicts: " + failures);
        new c6000.C6000CallAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, new MessageLog());
        for (var row : rows) {
            var item = row.getAsJsonObject();var instruction = getInstructionAt(toAddr(item.get("site").getAsLong()));
            if (instruction.getFlowType().isCall() != item.get("call").getAsBoolean()) throw new AssertionError("Analyzer disagrees: " + item);
        }
        println("C6000_DELAYED_CALL_SAFETY_OK cases=" + rows.size() + " accepted=" + accepted + " refused=" + (rows.size() - accepted));
    }
}
