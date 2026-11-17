// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B LDW masks, except through B15 (SPRAB89 3.2): a stack store read back through a B15 pop survives decompilation.
// Usage: C6000SpLoadMaskTest.java cases.json

import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

import com.google.gson.*;

import c6000.C6000PipelineContracts;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;

public class C6000SpLoadMaskTest extends GhidraScript {
    private static final Set<Long> MASKS = Set.of(0xfffffffcL, 0xfffffffeL, 0xfffffff8L);

    @Override
    protected void run() throws Exception {
        JsonArray rows = JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray();
        var context = currentProgram.getProgramContext();
        context.setValue(currentProgram.getRegister("AMR"), currentProgram.getMinAddress(), currentProgram.getMaxAddress(), BigInteger.ZERO);
        Register a4 = currentProgram.getRegister("A4");
        int checked = 0;
        List<String> failures = new ArrayList<>();
        for (JsonElement item : rows) {
            JsonObject r = item.getAsJsonObject();
            String name = r.get("name").getAsString();
            Address at = toAddr(r.get("entry").getAsLong());
            AddressSet body = new AddressSet(at, at.add(r.get("size").getAsLong() - 1));
            Function f = getFunctionAt(at);
            if (f == null) {
                new DisassembleCommand(body, body, true).applyTo(currentProgram, monitor);
                f = currentProgram.getFunctionManager().createFunction(name, at, body, SourceType.USER_DEFINED);
            }
            int sp = 0, masked = 0;
            for (Instruction insn : currentProgram.getListing().getInstructions(body, true)) {
                String m = insn.getMnemonicString().replaceAll("^_?(\\[[^]]*\\])?", "");
                if (!m.startsWith("LD")) continue;
                boolean mask = Arrays.stream(insn.getPcode()).anyMatch(op -> op.getOpcode() == PcodeOp.INT_AND && op.getInput(1).isConstant()
                    && MASKS.contains(op.getInput(1).getOffset() & 0xffffffffL));
                boolean viaSp = insn.toString().contains("B15");
                if (viaSp && mask) failures.add(name + ": masked load through B15: " + insn + " (" + insn.getLength() + " bytes)");
                if (!viaSp && !mask) failures.add(name + ": unmasked load: " + insn);
                if (viaSp) sp++; else masked++;
            }
            if (sp != r.get("sp").getAsInt() || masked != r.get("masked").getAsInt())
                failures.add(name + ": " + sp + " B15 loads, " + masked + " masked, want " + r.get("sp") + "/" + r.get("masked"));
            if (r.get("decompile").getAsBoolean()) {
                String nativeC = keptStore(name + " native", f, a4);
                long start = at.getOffset() & ~31L;
                var source = new C6000PipelineContracts.SourceWindow(start, 32, C6000PipelineContracts.sha256(getBytes(toAddr(start), 32)));
                var review = C6000PipelineContracts.review(currentProgram, f, "fixture entry: drained pipeline", Set.of(), List.of(source), monitor);
                C6000PipelineContracts.record(currentProgram, f, review, monitor);
                C6000PipelineContracts.activate(currentProgram, f, monitor);
                String scheduleC = keptStore(name + " schedule", f, a4);
                println(name + " native\n" + nativeC + "\n" + name + " schedule\n" + scheduleC);
                if (nativeC.startsWith("DROPPED")) failures.add(name + " native: argument store at entry SP dropped");
                if (scheduleC.startsWith("DROPPED")) failures.add(name + " schedule: argument store at entry SP dropped");
            }
            checked++;
        }
        if (!failures.isEmpty()) throw new AssertionError(failures.size() + " failures:\n  " + String.join("\n  ", failures));
        if (checked != 3) throw new AssertionError("expected three cases, checked " + checked);
        println("C6000_SP_LOAD_MASK_OK cases=" + checked);
    }

    // The entry argument must still be written to the stack (a COPY into a stack local or a STORE).
    private String keptStore(String label, Function f, Register a4) throws Exception {
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            DecompileResults result = decompiler.decompileFunction(f, 60, monitor);
            if (!result.decompileCompleted()) throw new AssertionError(label + ": decompiler: " + result.getErrorMessage());
            String c = result.getDecompiledFunction().getC();
            boolean kept = false;
            for (Iterator<PcodeOpAST> it = result.getHighFunction().getPcodeOps(); it.hasNext();) {
                PcodeOpAST op = it.next();
                boolean toStack = op.getOpcode() == PcodeOp.COPY && op.getOutput() != null
                    && op.getOutput().getAddress().getAddressSpace().isStackSpace();
                Varnode value = op.getOpcode() == PcodeOp.STORE ? op.getInput(2) : toStack ? op.getInput(0) : null;
                if (value != null && value.isInput() && value.isRegister() && value.getAddress().equals(a4.getAddress())) kept = true;
            }
            return (kept ? "" : "DROPPED ") + c;
        }
        finally {
            decompiler.dispose();
        }
    }
}
