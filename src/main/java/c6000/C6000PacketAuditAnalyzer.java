/* ### */
package c6000;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Revokes native packet staging when analysis discovers a packet-interior target. */
public final class C6000PacketAuditAnalyzer extends AbstractAnalyzer {
	public C6000PacketAuditAnalyzer() {
		super("C6000 Parallel-Read Packet Audit",
			"Refuses staged execute packets with an analyzed interior control-flow target",
			AnalyzerType.INSTRUCTION_ANALYZER);
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
		try {
			int refused = C6000PacketContext.audit(program, monitor);
			if (refused > 0) log.appendMsg(getName(), "refused " + refused +
				" packet(s) with interior targets");
			return true;
		}
		catch (CancelledException cancelled) {
			throw cancelled;
		}
		catch (Exception failure) {
			log.appendException(failure);
			return false;
		}
	}
}
