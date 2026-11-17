// SPDX-License-Identifier: Apache-2.0
package c6000;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Defers load results where exact (C6000NativeLoadLatencyScheduler), then warns where default lifting stays inexact (C6000NativeHazardWarning). */
public final class C6000NativeHazardAnalyzer extends AbstractAnalyzer {
    public static final String BOOKMARK = "C6000 Inexact Native Pipeline";

    public C6000NativeHazardAnalyzer() {
        super("C6000 Inexact Native Pipeline",
            "Defers native load results read in their delay slots where exact; bookmarks functions whose default lifting still mis-schedules result latency or branch windows",
            AnalyzerType.FUNCTION_ANALYZER);
        setDefaultEnablement(true);
        // After bodies, windows and any schedule activation are final.
        setPriority(AnalysisPriority.LOW_PRIORITY.after());
    }

    @Override
    public boolean canAnalyze(Program program) {
        return C6000PacketContext.isC6000(program);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        int transaction = program.startTransaction("C6000 inexact-pipeline warnings");
        boolean commit = false;
        try {
            var functions = new java.util.LinkedHashSet<Function>();
            for (var function : program.getFunctionManager().getFunctions(set, true)) functions.add(function);
            // Revalidate deferrals elsewhere: a reference added since may now enter their windows.
            functions.addAll(C6000NativeLoadLatencyScheduler.marked(program));
            for (var function : functions) {
                monitor.checkCancelled();
                if (function.isThunk() || function.isExternal()) continue;
                var manager = program.getBookmarkManager();
                manager.removeBookmarks(function.getBody(), BookmarkType.WARNING, BOOKMARK, monitor);
                try {
                    C6000NativeLoadLatencyScheduler.schedule(program, function, monitor);
                    var finding = C6000NativeHazardWarning.scan(program, function);
                    if (finding != null) {
                        manager.setBookmark(finding.at(), BookmarkType.WARNING, BOOKMARK, finding.reason());
                    }
                }
                catch (CancelledException cancelled) { throw cancelled; }
                catch (Exception skip) { /* an undecodable body is not our warning to make */ }
            }
            commit = true;
        }
        finally { program.endTransaction(transaction, commit); }
        return true;
    }
}
