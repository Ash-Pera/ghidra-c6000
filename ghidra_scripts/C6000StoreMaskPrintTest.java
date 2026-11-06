// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Decompiled stores keep the width mask on an unproven base and print without one on a proven aligned base.
// Usage: C6000StoreMaskPrintTest.java cases.json

import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

import com.google.gson.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;

public class C6000StoreMaskPrintTest extends GhidraScript {
    private static final Set<Long> MASKS = Set.of(0xfffffffeL, 0xfffffffcL, 0xfffffff8L);

    private static Varnode strip(Varnode v) {
        while (v.getDef() != null && (v.getDef().getOpcode() == PcodeOp.CAST || v.getDef().getOpcode() == PcodeOp.COPY))
            v = v.getDef().getInput(0);
        return v;
    }

    private static long widthMask(PcodeOp op) {
        if (op == null || op.getOpcode() != PcodeOp.INT_AND || !op.getInput(1).isConstant()) return 0;
        long m = op.getInput(1).getOffset() & 0xffffffffL;
        return MASKS.contains(m) ? m : 0;
    }

    private Function function(long entry, long size, String name) throws Exception {
        Address at = toAddr(entry);
        AddressSet body = new AddressSet(at, at.add(size - 1));
        new DisassembleCommand(body, body, true).applyTo(currentProgram, monitor);
        Function f = getFunctionAt(at);
        if (f != null) removeFunction(f);
        return currentProgram.getFunctionManager().createFunction(name, at, body, SourceType.USER_DEFINED);
    }

    @Override
    protected void run() throws Exception {
        JsonArray rows = JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray();
        var context = currentProgram.getProgramContext();
        Address lo = currentProgram.getMinAddress(), hi = currentProgram.getMaxAddress();
        context.setValue(currentProgram.getRegister("AMR"), lo, hi, BigInteger.ZERO);
        StructureDataType record = new StructureDataType("R", 0);
        for (int k = 0; k < 16; k++) record.add(CharDataType.dataType, "b" + k, null);
        currentProgram.getDataTypeManager().addDataType(record, null);
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decompiler.setOptions(options);
        decompiler.openProgram(currentProgram);
        int checked = 0;
        try {
            for (JsonElement item : rows) {
                JsonObject r = item.getAsJsonObject();
                String name = r.get("name").getAsString();
                long entry = r.get("entry").getAsLong();
                if (!r.get("b14").isJsonNull())
                    context.setValue(currentProgram.getRegister("B14"), toAddr(entry), toAddr(entry + 0xff),
                        BigInteger.valueOf(r.get("b14").getAsLong()));
                if (r.has("callee") && !r.get("callee").isJsonNull()) function(r.get("callee").getAsLong(), 8, name + "_callee");
                Function f = function(entry, r.get("size").getAsLong(), name);
                if (!r.get("signature").isJsonNull()) {
                    FunctionDefinitionDataType sig = CParserUtils.parseSignature((DataTypeManagerService) null, currentProgram,
                        r.get("signature").getAsString());
                    new ApplyFunctionSignatureCmd(f.getEntryPoint(), sig, SourceType.USER_DEFINED).applyTo(currentProgram, monitor);
                }
                DecompileResults result = decompiler.decompileFunction(f, 60, monitor);
                if (!result.decompileCompleted()) throw new AssertionError(name + ": decompiler: " + result.getErrorMessage());
                String c = result.getDecompiledFunction().getC();
                HighFunction high = result.getHighFunction();
                List<String> stores = new ArrayList<>();
                Set<String> ram = new TreeSet<>();
                int stack = 0, masks = 0;
                for (Iterator<PcodeOpAST> it = high.getPcodeOps(); it.hasNext();) {
                    PcodeOpAST op = it.next();
                    if (widthMask(op) != 0) masks++;
                    if (op.getOpcode() == PcodeOp.STORE) {
                        Varnode a = strip(op.getInput(1));
                        stores.add(op.getInput(2).getSize() + ":" + Long.toHexString(widthMask(a.getDef())));
                    }
                    Varnode out = op.getOutput();
                    if (out == null || op.getOpcode() == PcodeOp.INDIRECT) continue;
                    HighSymbol symbol = out.getHigh() == null ? null : out.getHigh().getSymbol();
                    if (symbol != null && symbol.getStorage().isStackStorage()) stack++;
                    else if (out.getAddress().isMemoryAddress())
                        ram.add(Long.toHexString(out.getOffset()) + ":" + out.getSize());
                }
                List<String> want = new ArrayList<>();
                for (JsonElement s : r.getAsJsonArray("stores")) {
                    JsonArray p = s.getAsJsonArray();
                    want.add(p.get(0).getAsInt() + ":" + Long.toHexString(p.get(1).getAsLong()));
                }
                Collections.sort(stores);
                Collections.sort(want);
                if (!stores.equals(want)) throw new AssertionError(name + ": stores " + stores + " expected " + want + "\n" + c);
                if (r.has("ram")) {
                    for (JsonElement s : r.getAsJsonArray("ram")) {
                        JsonArray p = s.getAsJsonArray();
                        String w = Long.toHexString(p.get(0).getAsLong()) + ":" + p.get(1).getAsInt();
                        if (!ram.contains(w)) throw new AssertionError(name + ": no write " + w + " in " + ram + "\n" + c);
                    }
                    if (ram.size() != r.getAsJsonArray("ram").size()) throw new AssertionError(name + ": writes " + ram + "\n" + c);
                }
                if (r.has("stack") && stack < r.get("stack").getAsInt())
                    throw new AssertionError(name + ": " + stack + " stack writes\n" + c);
                boolean printed = c.contains("0xfffffffe") || c.contains("0xfffffffc") || c.contains("0xfffffff8");
                if (r.has("no_mask") && (masks != 0 || printed)) throw new AssertionError(name + ": mask printed\n" + c);
                if (!want.isEmpty() && !printed) throw new AssertionError(name + ": mask not printed\n" + c);
                checked++;
            }
        }
        finally {
            decompiler.dispose();
        }
        if (checked < 6) throw new AssertionError("expected six cases, checked " + checked);
        println("C6000_STORE_MASK_PRINT_OK cases=" + checked);
    }
}
