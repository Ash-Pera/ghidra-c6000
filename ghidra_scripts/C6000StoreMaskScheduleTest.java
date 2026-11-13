// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B STW/STH/STDW masks, except through B15 (SPRAB89 3.2): no stack local is read unwritten in an exact schedule.
// Usage: C6000StoreMaskScheduleTest.java cases.json

import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

import com.google.gson.*;

import c6000.C6000PipelineContracts;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;

public class C6000StoreMaskScheduleTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        JsonArray rows = JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray();
        var context = currentProgram.getProgramContext();
        context.setValue(currentProgram.getRegister("AMR"), currentProgram.getMinAddress(), currentProgram.getMaxAddress(), BigInteger.ZERO);
        System.setProperty("c6000.opaqueCalls", "true");
        int checked = 0;
        try {
            for (JsonElement item : rows) {
                JsonObject r = item.getAsJsonObject();
                String name = r.get("name").getAsString();
                Address at = toAddr(r.get("entry").getAsLong());
                AddressSet body = new AddressSet(at, at.add(r.get("size").getAsLong() - 1));
                new DisassembleCommand(body, body, true).applyTo(currentProgram, monitor);
                Function f = currentProgram.getFunctionManager().createFunction(name, at, body, SourceType.USER_DEFINED);
                int sp = 0, masked = 0;
                for (Instruction insn : currentProgram.getListing().getInstructions(body, true)) {
                    String m = insn.getMnemonicString().replaceAll("^_?(\\[[^]]*\\])?", "");
                    if (!m.startsWith("STW") && !m.startsWith("STH") && !m.startsWith("STDW")) continue;
                    boolean mask = Arrays.stream(insn.getPcode()).anyMatch(op -> op.getOpcode() == PcodeOp.INT_AND && op.getInput(1).isConstant()
                        && Set.of(0xfffffffcL, 0xfffffffeL, 0xfffffff8L).contains(op.getInput(1).getOffset() & 0xffffffffL));
                    boolean viaSp = insn.toString().contains("B15");
                    if (viaSp && mask) throw new AssertionError(name + ": masked store through B15: " + insn);
                    if (!viaSp && !mask) throw new AssertionError(name + ": unmasked store: " + insn);
                    if (viaSp) sp++; else masked++;
                }
                if (r.has("sp") && (sp != r.get("sp").getAsInt() || masked != r.get("masked").getAsInt()))
                    throw new AssertionError(name + ": " + sp + " B15 stores, " + masked + " masked, want " + r.get("sp") + "/" + r.get("masked"));
                long start = at.getOffset() & ~31L;
                var source = new C6000PipelineContracts.SourceWindow(start, 32, C6000PipelineContracts.sha256(getBytes(toAddr(start), 32)));
                var review = C6000PipelineContracts.review(currentProgram, f, "fixture entry: drained pipeline", Set.of(), List.of(source), monitor);
                C6000PipelineContracts.record(currentProgram, f, review, monitor);
                C6000PipelineContracts.activate(currentProgram, f, monitor);
                DecompInterface decompiler = new DecompInterface();
                try {
                    decompiler.openProgram(currentProgram);
                    DecompileResults result = decompiler.decompileFunction(f, 60, monitor);
                    if (!result.decompileCompleted()) throw new AssertionError(name + ": decompiler: " + result.getErrorMessage());
                    String c = result.getDecompiledFunction().getC();
                    int calls = 0;
                    List<String> unset = new ArrayList<>();
                    for (Iterator<PcodeOpAST> it = result.getHighFunction().getPcodeOps(); it.hasNext();) {
                        PcodeOpAST op = it.next();
                        if (op.getOpcode() == PcodeOp.CALLIND) calls++;
                        for (Varnode in : op.getInputs())
                            if (in.isInput() && in.getAddress().getAddressSpace().isStackSpace() && op.getOpcode() != PcodeOp.INDIRECT)
                                unset.add(in.toString());
                    }
                    if (calls != r.get("calls").getAsInt()) throw new AssertionError(name + ": " + calls + " CALLIND\n" + c);
                    if (!unset.isEmpty()) throw new AssertionError(name + ": stack read before written " + unset + "\n" + c);
                    println(name + "\n" + c);
                }
                finally {
                    decompiler.dispose();
                }
                checked++;
            }
        }
        finally {
            System.clearProperty("c6000.opaqueCalls");
        }
        if (checked < 2) throw new AssertionError("expected two cases, checked " + checked);
        println("C6000_STORE_MASK_SCHEDULE_OK cases=" + checked);
    }
}
