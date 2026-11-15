// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Opt-in: exact schedules for functions no review covers, under an assumed drained entry.
 * Native lifting assumes the same and more (every write lands at once); nothing here proves
 * that a caller enters drained (SPRUFE8B 3.5, 4.2). Each applied schedule gets a warning bookmark.
 */
public final class C6000AssumedSchedules {
    public static final String EVIDENCE =
        "assumed drained entry (C6000 Assumed-Drained Schedules option): no caller proof";
    public static final String BOOKMARK = "C6000 Assumed-Drained Schedule";
    private static final Pattern BRANCH = Pattern.compile("^(\\[!?[AB][0-2]\\])?\\s*(B|BNOP|CALLP)(\\.|\\s|$)");

    public record Outcome(int applied, int kept, List<String> refused) {}

    private C6000AssumedSchedules() {}

    /** Applies to every function in `set` (all when null) without a review of its own. */
    public static Outcome apply(Program program, AddressSetView set, TaskMonitor monitor)
            throws CancelledException {
        int applied = 0, kept = 0;
        List<String> refused = new ArrayList<>();
        var functions = set == null ? program.getFunctionManager().getFunctions(true)
            : program.getFunctionManager().getFunctions(set, true);
        List<Function> list = new ArrayList<>();
        while (functions.hasNext()) list.add(functions.next());
        for (Function function : list) {
            monitor.checkCancelled();
            if (function.isThunk() || function.isExternal()) continue;
            Address entry = function.getEntryPoint();
            if (C6000PipelineContracts.isRecorded(program, function)) {
                if (!EVIDENCE.equals(C6000PipelineContracts.recordedReview(program, function).evidence())) continue;
                try {
                    C6000PipelineContracts.activate(program, function, monitor);
                    kept++;
                    continue;
                }
                catch (CancelledException cancelled) { throw cancelled; }
                catch (Exception stale) {
                    // A changed function is reviewed again below.
                    disable(program, function, monitor);
                }
            }
            if (active(program, entry)) continue;
            try {
                String why = entryRefusal(program, entry);
                if (why != null) throw new IllegalArgumentException(why);
                var review = C6000PipelineContracts.review(program, function, EVIDENCE, Set.of(),
                    List.of(window(program, entry)), monitor);
                C6000PipelineContracts.record(program, function, review, monitor);
                C6000PipelineContracts.activate(program, function, monitor);
                program.getBookmarkManager().setBookmark(entry, BookmarkType.WARNING, BOOKMARK,
                    "exact schedule under an assumed drained entry; a caller entering with writes or branches in flight is not modelled");
                applied++;
            }
            catch (CancelledException cancelled) { throw cancelled; }
            catch (Exception refusal) {
                disable(program, function, monitor);
                refused.add(entry + ": " + refusal.getMessage());
            }
        }
        return new Outcome(applied, kept, List.copyOf(refused));
    }

    private static void disable(Program program, Function function, TaskMonitor monitor)
            throws CancelledException {
        try {
            if (C6000PipelineContracts.isRecorded(program, function) &&
                    !EVIDENCE.equals(C6000PipelineContracts.recordedReview(program, function).evidence())) return;
            C6000PipelineSchedules.disable(program, function, monitor);
            program.getBookmarkManager().removeBookmarks(
                new ghidra.program.model.address.AddressSet(function.getEntryPoint()),
                BookmarkType.WARNING, BOOKMARK, monitor);
        }
        catch (CancelledException cancelled) { throw cancelled; }
        catch (Exception ignored) { /* nothing was enabled */ }
    }

    private static boolean active(Program program, Address entry) {
        return BigInteger.ONE.equals(program.getProgramContext().getValue(
            program.getRegister("c_schedule_entry"), entry, false));
    }

    private static C6000PipelineContracts.SourceWindow window(Program program, Address entry)
            throws Exception {
        Address start = entry.getNewAddress(entry.getOffset() & ~31L);
        byte[] bytes = new byte[32];
        if (program.getMemory().getBytes(start, bytes) != 32) {
            throw new IllegalArgumentException("entry fetch packet is not wholly initialized");
        }
        return new C6000PipelineContracts.SourceWindow(start.getOffset(), 32,
            C6000PipelineContracts.sha256(bytes));
    }

    /** An entry packet with a branch, or an entry issued within five cycles of a branch, keeps native lifting. */
    static String entryRefusal(Program program, Address entry) throws Exception {
        var listing = program.getListing();
        List<Address> prefix = C6000ExecutionPackets.issuePrefix(program, entry);
        Address start = prefix.isEmpty() ? entry : prefix.get(0);
        for (Address member : C6000ExecutionPackets.packetMembers(program, start)) {
            Instruction instruction = listing.getInstructionAt(member);
            if (instruction != null && branch(instruction)) return "a branch issues in the entry packet";
        }
        int cycles = 0;
        Address at = start;
        while (cycles < 5) {
            Instruction before = listing.getInstructionBefore(at);
            if (before == null || before.getMaxAddress().next() == null ||
                    !before.getMaxAddress().next().equals(at)) break;
            List<Address> earlier = C6000ExecutionPackets.issuePrefix(program, before.getAddress());
            Address first = earlier.isEmpty() ? before.getAddress() : earlier.get(0);
            int span = 1;
            for (Address member : C6000ExecutionPackets.packetMembers(program, first)) {
                Instruction instruction = listing.getInstructionAt(member);
                if (instruction == null) continue;
                if (branch(instruction)) return "the entry issues in the delay window of " + member;
                span = Math.max(span, nopCycles(instruction));
            }
            cycles += span;
            at = first;
        }
        return null;
    }

    private static boolean branch(Instruction instruction) {
        return BRANCH.matcher(instruction.getMnemonicString()).find();
    }

    private static int nopCycles(Instruction instruction) {
        if (!instruction.getMnemonicString().equals("NOP")) return 1;
        Object[] operands = instruction.getOpObjects(0);
        if (operands.length == 1 && operands[0] instanceof ghidra.program.model.scalar.Scalar s) {
            return (int) s.getUnsignedValue();
        }
        return 1;
    }
}
