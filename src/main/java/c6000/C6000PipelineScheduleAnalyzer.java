// SPDX-License-Identifier: Apache-2.0
package c6000;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** No function acquires an assumed empty pipeline merely by being discovered. */
public final class C6000PipelineScheduleAnalyzer extends AbstractAnalyzer {
    public C6000PipelineScheduleAnalyzer() {
        super("C6000 Reviewed Pipeline Schedules",
            "Activates exact packet scheduling only for recorded, unchanged entry contracts",
            AnalyzerType.FUNCTION_ANALYZER);
        setDefaultEnablement(true);
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
    }

    @Override
    public boolean canAnalyze(Program program) {
        return C6000PacketContext.isC6000(program);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        // A reference or caller-byte edit can invalidate a contract outside `set`.
        // Only explicitly recorded functions are compiled; all others are untouched.
        var functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            var function = functions.next();
            if (!C6000PipelineContracts.isRecorded(program, function)) continue;
            try {
                C6000PipelineContracts.activate(program, function, monitor);
            }
            catch (CancelledException cancelled) {
                throw cancelled;
            }
            catch (Exception refused) {
                // Do not silently switch a stale exact representation back to
                // sequential effects. The injection library also refuses it.
                log.appendMsg(getName(), function.getEntryPoint() + ": " + refused.getMessage());
            }
        }
        return true;
    }
}
