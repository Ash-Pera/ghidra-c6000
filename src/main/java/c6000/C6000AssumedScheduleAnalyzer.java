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

/** Opt-in (off by default; -Dc6000.assumeDrainedSchedules=true enables it): see C6000AssumedSchedules. */
public final class C6000AssumedScheduleAnalyzer extends AbstractAnalyzer {
    public C6000AssumedScheduleAnalyzer() {
        super("C6000 Assumed-Drained Schedules",
            "Applies exact packet schedules to unreviewed functions under an assumed drained entry pipeline (warning bookmark on each)",
            AnalyzerType.FUNCTION_ANALYZER);
        setDefaultEnablement(Boolean.getBoolean("c6000.assumeDrainedSchedules"));
        // After every flow and body pass, so the source each schedule pins is final.
        setPriority(AnalysisPriority.LOW_PRIORITY);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return C6000PacketContext.isC6000(program);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        var outcome = C6000AssumedSchedules.apply(program, set, monitor);
        for (String refusal : outcome.refused()) log.appendMsg(getName(), refusal);
        return true;
    }
}
