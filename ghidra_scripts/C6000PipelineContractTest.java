// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Independent issue #16 old-value expectations plus source/review/refusal checks.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.*;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.pcode.exec.*;
import ghidra.util.task.*;
import java.nio.file.*;
import java.math.BigInteger;
import java.util.*;
import com.google.gson.*;
import c6000.*;

public class C6000PipelineContractTest extends GhidraScript {
    private static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();
    private int refused;
    interface Action { void run() throws Exception; }

    void equal(Object expected, Object actual, String message) {
        if (!Objects.equals(expected, actual)) throw new AssertionError(message + " expected=" + expected + " actual=" + actual);
    }
    void refuses(Action action, String reason) throws Exception {
        try { action.run(); }
        catch (Exception error) {
            if (!error.toString().contains(reason)) throw new AssertionError("Wrong refusal: " + error, error);
            refused++;return;
        }
        throw new AssertionError("Accepted invalid contract: " + reason);
    }
    boolean enabled(Function function) {
        return BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
            currentProgram.getRegister("c_schedule_entry"), function.getEntryPoint(), false));
    }
    Function function(long entry, String name) throws Exception {
        Address at = toAddr(entry);
        new DisassembleCommand(at, new AddressSet(at, at.add(0x1f)), false).applyTo(currentProgram, monitor);
        return currentProgram.getFunctionManager().createFunction(name, at,
            new AddressSet(at, at.add(entry == 0x1e00 ? 0x1f : 0x9f)), SourceType.USER_DEFINED);
    }
    void inject(Function function) throws Exception {
        var context = new InjectContext();context.baseAddr = function.getEntryPoint();
        new C6000PipelinePayload("contract-regression").getPcode(currentProgram, context);
    }
    void stale(Function function, Action mutation, Action restore, String reason) throws Exception {
        try { mutation.run();refuses(() -> inject(function), reason); }
        finally { restore.run(); }
        inject(function);
    }
    void patch(long pc, int value) throws Exception {
        var at = toAddr(pc);
        var refs = currentProgram.getReferenceManager().getReferencesFrom(at);
        var old = getInstructionAt(at);
        var flow = old == null ? FlowOverride.NONE : old.getFlowOverride();
        currentProgram.getListing().clearCodeUnits(at, at.add(3), false);
        currentProgram.getMemory().setInt(at, value);
        new DisassembleCommand(at, new AddressSet(at, at.add(3)), false).applyTo(currentProgram, monitor);
        getInstructionAt(at).setFlowOverride(flow);
        for (var ref : refs) currentProgram.getReferenceManager().addReference(ref);
    }
    void selector(boolean enabled) throws Exception {
        var at = toAddr(0x1000);var refs = currentProgram.getReferenceManager().getReferencesFrom(at);
        currentProgram.getListing().clearCodeUnits(at, at.add(3), false);
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("c_schedule_entry"),
            at, at, enabled ? BigInteger.ONE : BigInteger.ZERO);
        new DisassembleCommand(at, new AddressSet(at, at.add(3)), false).applyTo(currentProgram, monitor);
        for (var ref : refs) currentProgram.getReferenceManager().addReference(ref);
    }
    JsonObject manifest(List<Function> functions, C6000PipelineContracts.SourceWindow source) {
        var plan = new JsonObject();plan.addProperty("schema", 1);
        plan.addProperty("language_id", currentProgram.getLanguageID().getIdAsString());
        var rows = new JsonArray();
        for (var function : functions) {
            var row = new JsonObject();row.addProperty("entry", function.getEntryPoint().getOffset());
            row.addProperty("drained_entry_evidence", "Synthetic reset entry: no incoming instructions or pending effects; the source window pins this fixture");
            row.add("previous_e1_writes", new JsonArray());
            var sources = new JsonArray();sources.add(JSON.toJsonTree(source));row.add("entry_sources", sources);rows.add(row);
        }
        plan.add("functions", rows);return plan;
    }
    String digest(Path path) throws Exception { return C6000PipelineContracts.sha256(Files.readAllBytes(path)); }
    void workflow(Path manifest, Path report, String... action) throws Exception {
        List<String> args = new ArrayList<>(List.of(manifest.toString(), report.toString()));
        args.addAll(List.of(action));runScript("C6000ReviewPipelineSchedules.java", args.toArray(String[]::new));
    }
    long execute(C6000PipelineCompiler.Result result, JsonObject item) throws Exception {
        var language = (SleighLanguage) currentProgram.getLanguage();
        var arithmetic = BytesPcodeArithmetic.forLanguage(language);
        var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
        for (var register : language.getRegisters()) if (!register.isProcessorContext() && register.getMinimumByteSize() == 4) state.setVar(register, arithmetic.fromConst(0, 4));
        state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
        for (var input : item.getAsJsonObject("inputs").entrySet()) state.setVar(currentProgram.getRegister(input.getKey()), arithmetic.fromConst(input.getValue().getAsLong(), 4));
        state.setVar(toAddr(0x8000), 128, false, new byte[128]);
        state.setVar(toAddr(0x8000), 4, false, arithmetic.fromConst(0x11223344, 4));
        state.setVar(toAddr(0x8004), 4, false, arithmetic.fromConst(0x22334455, 4));
        var executor = new PcodeExecutor<byte[]>(language, arithmetic, state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
        var library = PcodeUseropLibrary.<byte[]>nil();
        var frame = executor.begin(new PcodeProgram(language, Arrays.asList(result.code()), library.getSymbols(language)) {});
        int steps = 0;while (!frame.isFinished() && steps++ < 100000) executor.step(frame, library);
        if (!frame.isFinished()) throw new AssertionError("schedule step bound");
        return arithmetic.toLong(state.getVar(currentProgram.getRegister(item.get("output").getAsString()),
            PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT);
    }
    @Override
    protected void run() throws Exception {
        Path directory = Paths.get(getScriptArgs()[0]).toAbsolutePath().getParent();
        var rows = JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray();
        C6000PacketContext.prime(currentProgram, monitor);
        currentProgram.getMemory().createInitializedBlock("contract_ram", toAddr(0x8000), 0x100, (byte) 0, monitor, false);
        currentProgram.getMemory().setInt(toAddr(0x8000), 0x11223344);currentProgram.getMemory().setInt(toAddr(0x8004), 0x22334455);
        byte[] sourceBytes = new byte[32];currentProgram.getMemory().getBytes(toAddr(0x3000), sourceBytes);
        var source = new C6000PipelineContracts.SourceWindow(0x3000, 32, C6000PipelineContracts.sha256(sourceBytes));
        var functions = new ArrayList<Function>();
        for (var value : rows) {
            var item = value.getAsJsonObject();var f = function(item.get("entry").getAsLong(), item.get("name").getAsString());functions.add(f);
            EmulatorHelper emulator = new EmulatorHelper(currentProgram);
            try {
                for (var input : item.getAsJsonObject("inputs").entrySet()) emulator.writeRegister(input.getKey(), input.getValue().getAsLong());
                emulator.getEmulator().setExecuteAddress(f.getEntryPoint().getOffset());
                for (int k = 0; k < 2; k++) if (!emulator.step(monitor)) throw new AssertionError(emulator.getLastError());
                equal(item.get("raw").getAsLong(), emulator.readRegister(item.get("output").getAsString()).longValue() & 0xffffffffL, "raw baseline");
            } finally { emulator.dispose(); }
        }
        var parallel = functions.get(0);parallel.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
        currentProgram.getListing().setComment(parallel.getEntryPoint(), CommentType.PLATE, "Keep reviewed annotation");
        var reference = currentProgram.getReferenceManager().addMemoryReference(parallel.getEntryPoint(), toAddr(0x3000), RefType.DATA, SourceType.USER_DEFINED, 0);
        var analyzer = new C6000PipelineScheduleAnalyzer();long untouched = currentProgram.getModificationNumber();
        analyzer.added(currentProgram, currentProgram.getMemory(), monitor, new MessageLog());
        equal(untouched, currentProgram.getModificationNumber(), "unreviewed analyzer must be read-only");
        for (var f : functions) equal(false, enabled(f), "unreviewed function untouched");
        var unsupported = function(0x1e00, "unsupported_phase");
        var reviewFunctions = new ArrayList<>(functions);reviewFunctions.add(unsupported);
        Path manifest = directory.resolve("review-manifest.json"), report = directory.resolve("review-report.json");
        Files.writeString(manifest, JSON.toJson(manifest(reviewFunctions, source)));
        long before = currentProgram.getModificationNumber();workflow(manifest, report);
        equal(before, currentProgram.getModificationNumber(), "report read-only");
        var reportObject = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
        equal(3, reportObject.get("eligible_count").getAsInt(), "eligible reviewed functions");
        equal("refused", reportObject.getAsJsonArray("functions").get(3).getAsJsonObject().get("status").getAsString(), "unsupported refusal");
        refuses(() -> workflow(manifest, report, "apply", "0".repeat(64)), "review report SHA changed");
        workflow(manifest, report, "record", digest(report));
        for (var f : functions) equal(false, enabled(f), "record alone must not enable");
        analyzer.added(currentProgram, currentProgram.getMemory(), monitor, new MessageLog());
        for (int k = 0; k < functions.size(); k++) {
            var f = functions.get(k);equal(true, enabled(f), "recorded analyzer activation");
            var result = C6000PipelineContracts.activate(currentProgram, f, monitor);
            equal(rows.get(k).getAsJsonObject().get("expected").getAsLong(), execute(result, rows.get(k).getAsJsonObject()), "scheduled old values");
            inject(f);
        }
        equal("Keep reviewed annotation", currentProgram.getListing().getComment(CommentType.PLATE, parallel.getEntryPoint()), "comment retained");
        if (currentProgram.getReferenceManager().getReference(reference.getFromAddress(), reference.getToAddress(), reference.getOperandIndex()) == null) throw new AssertionError("reference lost");
        long repeated = currentProgram.getModificationNumber();analyzer.added(currentProgram, currentProgram.getMemory(), monitor, new MessageLog());
        equal(repeated, currentProgram.getModificationNumber(), "repeat analyzer idempotent");
        var cancelled = new TaskMonitorAdapter(true);cancelled.cancel();
        refuses(() -> analyzer.added(currentProgram, currentProgram.getMemory(), cancelled, new MessageLog()), "CancelledException");
        equal(repeated, currentProgram.getModificationNumber(), "cancellation is read-only");
        stale(parallel, () -> selector(false), () -> selector(true), "entry selector changed");
        int entryWord = currentProgram.getMemory().getInt(toAddr(0x1000));
        stale(parallel, () -> patch(0x1000, entryWord ^ 0x80), () -> patch(0x1000, entryWord), "stale");
        stale(parallel, () -> currentProgram.getMemory().setInt(toAddr(0x3000), 0x2000),
            () -> currentProgram.getMemory().setInt(toAddr(0x3000), 0), "entry-source bytes changed");
        var rs = currentProgram.getRegister("c_rs");
        var oldContext = currentProgram.getProgramContext().getRegisterValue(rs, toAddr(0x3000));
        stale(parallel, () -> currentProgram.getProgramContext().setValue(rs, toAddr(0x3000), toAddr(0x3000), BigInteger.ONE),
            () -> {currentProgram.getProgramContext().remove(toAddr(0x3000), toAddr(0x3000), rs);
                if (oldContext != null) currentProgram.getProgramContext().setRegisterValue(toAddr(0x3000), toAddr(0x3000), oldContext);}, "stale");
        stale(parallel, () -> currentProgram.getReferenceManager().addMemoryReference(toAddr(0x3800), toAddr(0x1004), RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0),
            () -> currentProgram.getReferenceManager().delete(currentProgram.getReferenceManager().getReference(toAddr(0x3800), toAddr(0x1004), 0)), "alternate entry");
        stale(parallel, () -> currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1004)),
            () -> currentProgram.getSymbolTable().removeExternalEntryPoint(toAddr(0x1004)), "alternate entry");
        stale(parallel, () -> getInstructionAt(toAddr(0x1000)).setFlowOverride(FlowOverride.BRANCH),
            () -> getInstructionAt(toAddr(0x1000)).setFlowOverride(FlowOverride.NONE), "stale");
        String oldEvidence = currentProgram.getOptions(C6000PipelineSchedules.OPTIONS).getString(C6000PipelineSchedules.contractKey(parallel), "");
        stale(parallel, () -> currentProgram.getOptions(C6000PipelineSchedules.OPTIONS).setString(C6000PipelineSchedules.contractKey(parallel), "changed entry assumptions"),
            () -> currentProgram.getOptions(C6000PipelineSchedules.OPTIONS).setString(C6000PipelineSchedules.contractKey(parallel), oldEvidence), "entry assumptions changed");
        refuses(() -> C6000PipelineContracts.review(currentProgram, unsupported, "entry review", Set.of(), List.of(source), monitor), "unimplemented phase contract");
        refuses(() -> C6000PipelineContracts.review(currentProgram, parallel, "", Set.of(), List.of(source), monitor), "drained-entry evidence");
        refuses(() -> C6000PipelineContracts.review(currentProgram, parallel, "review", Set.of(), List.of(), monitor), "pin the source");
        var renewed = C6000PipelineContracts.review(currentProgram, parallel,
            "Re-reviewed synthetic reset entry", Set.of(), List.of(source), monitor);
        C6000PipelineContracts.record(currentProgram, parallel, renewed, monitor);
        refuses(() -> inject(parallel), "not been activated");
        analyzer.added(currentProgram, currentProgram.getMemory(), monitor, new MessageLog());inject(parallel);
        var pending = function(0x1300, "pending_stale");
        var pendingReview = C6000PipelineContracts.review(currentProgram, pending, "Synthetic reset entry", Set.of(), List.of(source), monitor);
        C6000PipelineContracts.record(currentProgram, pending, pendingReview, monitor);
        int pendingWord = currentProgram.getMemory().getInt(toAddr(0x1300));
        try {
            patch(0x1300, pendingWord ^ 0x80);
            var log = new MessageLog();analyzer.added(currentProgram, currentProgram.getMemory(), monitor, log);
            equal(false, enabled(pending), "stale pending record never enabled");
            if (!log.toString().contains("stale")) throw new AssertionError("missing refusal diagnostic");
        } finally { patch(0x1300, pendingWord); }
        var direct = function(0x1900, "direct_apply");
        Path directManifest = directory.resolve("direct-manifest.json"), directReport = directory.resolve("direct-report.json");
        Files.writeString(directManifest, JSON.toJson(manifest(List.of(direct), source)));
        workflow(directManifest, directReport);workflow(directManifest, directReport, "apply", digest(directReport));
        equal(true, enabled(direct), "reviewed direct apply");
        var compact = function(0x2400, "compact_structural_header");
        var compactReview = C6000PipelineContracts.review(currentProgram, compact,
            "Synthetic reset entry across compact fetch metadata", Set.of(), List.of(source), monitor);
        C6000PipelineContracts.record(currentProgram, compact, compactReview, monitor);
        C6000PipelineContracts.activate(currentProgram, compact, monitor);inject(compact);
        var staleContext = function(0x2200, "stale_physical_context");
        currentProgram.getListing().clearCodeUnits(toAddr(0x2204), toAddr(0x2207), false);
        currentProgram.getProgramContext().setValue(rs, toAddr(0x2204), toAddr(0x2204), BigInteger.ONE);
        refuses(() -> C6000PipelineContracts.review(currentProgram, staleContext,
            "Synthetic reset entry", Set.of(), List.of(source), monitor), "stored packet context conflicts");
        var decompiler = new DecompInterface();decompiler.setOptions(new DecompileOptions());decompiler.openProgram(currentProgram);
        try {
            var result = decompiler.decompileFunction(parallel, 30, monitor);
            if (!result.decompileCompleted()) throw new AssertionError(result.getErrorMessage());
            String code = result.getDecompiledFunction().getC();
            if (code.contains("return 1;") || code.contains("c6000_pipeline")) throw new AssertionError("sequential/opaque decompilation: " + code);
            Files.writeString(directory.resolve("scheduled.c"), code);
        } finally { decompiler.dispose(); }
        println("C6000_PIPELINE_CONTRACT_OK cases=" + rows.size() + " refusals=" + refused + " native_decompiler=true");
    }
}
