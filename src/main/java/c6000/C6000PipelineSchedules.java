// SPDX-License-Identifier: Apache-2.0
package c6000;
import java.math.BigInteger;
import java.util.EnumMap;
import java.util.Set;
import java.util.TreeSet;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
/** Explicit opt-in, never an automatic analyzer. See docs/pipeline-schedules.md. */
public final class C6000PipelineSchedules {
    public static final String OPTIONS = "C6000 pipeline schedules";

    private C6000PipelineSchedules() {
    }

    public static String contractKey(Function function) {
        return "Drained entry contract " + function.getEntryPoint();
    }

    public static String hazardsKey(Function function) {
        return "Previous E1 writes " + function.getEntryPoint();
    }
    /**
    * Compile before changing the listing. The caller must establish that there
    * are no pending writes or transfers at function entry,
    * and describe that evidence in drainedEntryContract. This is a precondition,
    * not something inferred from a C signature or an ordinary function boundary.
    * SPRUFE8B 3.5, 3.8.3 and 4.2 describe effects crossing such boundaries.
    */

    public static C6000PipelineCompiler.Result enable(Program program, Function function,             String drainedEntryContract, Set<String> previousE1Writes, TaskMonitor monitor) throws Exception {
        if (drainedEntryContract == null || drainedEntryContract.isBlank()) {
            throw new IllegalArgumentException("Evidence for a drained entry pipeline is required");
        }
        monitor.checkCancelled();
        var result = new C6000PipelineCompiler(program, function, previousE1Writes).compile();
        var at = function.getEntryPoint();
        var context = program.getProgramContext();
        var enabled = context.getValue(program.getRegister("c_schedule_entry"), at, false);
        if (BigInteger.ONE.equals(enabled)) {
            if (!String.join(",",new TreeSet<>(previousE1Writes)).equals(program.getOptions(OPTIONS).getString(hazardsKey(function), "")) || !drainedEntryContract.equals(program.getOptions(OPTIONS)                     .getString(contractKey(function), null))) {
                throw new IllegalArgumentException("Entry already enabled with a different contract");
            }
            return result;
        }
        var listing = program.getListing();
        var old = listing.getInstructionAt(at);
        if (old == null || old.getDelaySlotDepth() != 0 || old.isInDelaySlot()) {
            throw new IllegalArgumentException("Entry must be a defined instruction without native delay slots");
        }
        int length = old.getLength();
        var references = old.getReferencesFrom();
        var flow = old.getFlowOverride();
        boolean fallThroughOverridden = old.isFallThroughOverridden();
        var fallThrough = old.getFallThrough();
        var comments = new EnumMap<CommentType, String>(CommentType.class);
        for (var type : CommentType.values()) {
            var comment = listing.getComment(type, at);
            if (comment != null) comments.put(type, comment);
        }
        int transaction = program.startTransaction("Enable exact C6000 pipeline schedule");
        boolean commit = false;
        try {
            listing.clearCodeUnits(at, at.add(length - 1), false);
            context.setValue(program.getRegister("c_schedule_entry"), at, at, BigInteger.ONE);
            var command = new DisassembleCommand(at, new AddressSet(at, at.add(length - 1)), false);
            if (!command.applyTo(program, monitor)) {
                throw new IllegalStateException("Cannot decode scheduled entry: " + command.getStatusMsg());
            }
            var instruction = listing.getInstructionAt(at);
            if (instruction == null || instruction.getLength() != length) {
                throw new IllegalStateException("Scheduled entry changed instruction extent");
            }
            instruction.setFlowOverride(flow);
            if (fallThroughOverridden) instruction.setFallThrough(fallThrough);
            for (var item : comments.entrySet()) listing.setComment(at, item.getKey(), item.getValue());
            for (var reference : references) program.getReferenceManager().addReference(reference);
            var body = new AddressSet(function.getBody());
            body.add(result.covered());
            function.setBody(body);
            program.getOptions(OPTIONS).setString(contractKey(function), drainedEntryContract);
            program.getOptions(OPTIONS).setString(hazardsKey(function), String.join(",", new TreeSet<>(previousE1Writes)));
            monitor.checkCancelled();
            commit = true;
            return result;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
    }
}
