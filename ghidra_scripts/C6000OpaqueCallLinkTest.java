// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Local gate model (-Dc6000.opaqueCalls): an opaque call's B3 link written under the call's own
// predicate, the if/else call pair, in a tests/fixtures/nested-window-schedule.py image.
// Run after C6000NestedWindowScheduleTest.java prepare.

import c6000.C6000PipelineContracts;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.util.List;
import java.util.Set;

public class C6000OpaqueCallLinkTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		System.setProperty("c6000.opaqueCalls", "true");
		try {
			// Known-good: [!A1] MVKL/MVKH B3 on the [!A1] call's own fork.
			review(getFunctionAt(toAddr(0x1040L)));
			// Known-good: the link written in the call's own issue packet, before its predicate forks.
			review(getFunctionAt(toAddr(0x10e0L)));
			// Known-bad: the link is written under [B0], unknown on the call path.
			try {
				review(getFunctionAt(toAddr(0x1080L)));
				throw new AssertionError("accepted a link written under an unrelated predicate");
			}
			catch (IllegalArgumentException e) {
				if (!e.getMessage().contains("opaque call lacks an exact B3 link proof")) throw e;
			}
		}
		finally {
			System.clearProperty("c6000.opaqueCalls");
		}
		println("C6000_OPAQUE_CALL_LINK_OK checks=3");
	}

	private void review(Function f) throws Exception {
		long start = f.getEntryPoint().getOffset() & ~31L;
		byte[] bytes = getBytes(toAddr(start), 32);
		var source = new C6000PipelineContracts.SourceWindow(start, 32, C6000PipelineContracts.sha256(bytes));
		C6000PipelineContracts.review(currentProgram, f, "fixture entry: drained pipeline", Set.of(), List.of(source), monitor);
	}
}
