// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Applies C6000 Assumed-Drained Schedules to every unreviewed function, as the opt-in analyzer does. [REFUSALS_OUT]
import java.nio.file.Files;
import java.nio.file.Path;
import c6000.C6000AssumedSchedules;
import ghidra.app.script.GhidraScript;

public class C6000ApplyAssumedSchedules extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var outcome = C6000AssumedSchedules.apply(currentProgram, null, monitor);
        if (getScriptArgs().length == 1) Files.write(Path.of(getScriptArgs()[0]), outcome.refused());
        println("C6000_ASSUMED_SCHEDULES_OK applied=" + outcome.applied() + " kept=" + outcome.kept() +
            " refused=" + outcome.refused().size());
    }
}
