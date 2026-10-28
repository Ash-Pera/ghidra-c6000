// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Explicit opt-in. Usage: <function-entry-hex> <drained-entry-evidence> <previous-E1-GPRs-csv-or-dash>
import java.util.Set;
import ghidra.app.script.GhidraScript;
public class C6000EnablePipelineSchedule extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("Expected entry address, drained-entry evidence, previous E1 GPRs (CSV or -)");
        }
        var function = currentProgram.getFunctionManager().getFunctionAt(toAddr(args[0]));
        if (function == null) throw new IllegalArgumentException("No function at " + args[0]);
        Set<String> hazards = args[2].equals("-") ? Set.of() : Set.of(args[2].split(","));
        var result = c6000.C6000PipelineSchedules.enable(currentProgram, function, args[1], hazards, monitor);
        println("Enabled exact schedule: " + function.getName() + ", " + result.states() +
            " states, " + result.code().length + " p-code operations");
    }
}
