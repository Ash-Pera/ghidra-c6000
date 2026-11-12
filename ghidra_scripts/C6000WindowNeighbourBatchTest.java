// SPDX-License-Identifier: Apache-2.0
// @category C6000
// A batch that reviews a recorded schedule again judges an absorber by the new review,
// in a tests/fixtures/nested-window-schedule.py image. Run after C6000NestedWindowScheduleTest.java prepare.

import c6000.C6000PipelineContracts;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

public class C6000WindowNeighbourBatchTest extends GhidraScript {
	private static final String EVIDENCE = "fixture entry: drained pipeline";
	private int checks;

	@Override
	protected void run() throws Exception {
		// retjump stands for any recorded schedule that pins the absorber's shared packet.
		Function absorber = getFunctionAt(toAddr(0x112cL)), retjump = getFunctionAt(toAddr(0x1000L));
		if (absorber == null || retjump == null || getFunctionContaining(toAddr(0x1134L)) != null) {
			throw new AssertionError("fixture shape changed: " + absorber + ", " + retjump);
		}
		// Its recorded review pins the absorber's shared packet 0x1120 as an entry source.
		var pinned = List.of(source(retjump), window(0x1120L));
		C6000PipelineContracts.record(currentProgram, retjump,
			C6000PipelineContracts.review(currentProgram, retjump, EVIDENCE, Set.of(), pinned, monitor), monitor);
		Path directory = Files.createTempDirectory("c6000-window-neighbour-batch");
		Path manifest = directory.resolve("manifest.json"), report = directory.resolve("report.json");
		// Known-bad: the batch's new review of retjump is refused, so its recorded one stays.
		Files.writeString(manifest, manifest(Map.of(absorber, List.of(source(absorber)), retjump, List.of(source(retjump))),
			Map.of(retjump, ""), absorber, retjump));
		var rows = report(manifest, report);
		if (!reason(rows, 0).contains("would change the reviewed source of 00001000") || !reason(rows, 1).contains("evidence")) {
			throw new AssertionError("absorber must stay refused while retjump's recorded review pins 0x1120: " + rows);
		}
		checks++;
		// Known-good: the batch records retjump again without the shared packet before any enable,
		// whatever the manifest order (absorber first here).
		Files.writeString(manifest, manifest(Map.of(absorber, List.of(source(absorber)), retjump, List.of(source(retjump))),
			Map.of(), absorber, retjump));
		rows = report(manifest, report);
		if (!status(rows, 0).equals("eligible") || !status(rows, 1).equals("eligible")) {
			throw new AssertionError("batch re-reviewing retjump must keep the absorber eligible: " + rows);
		}
		checks++;
		String digest = C6000PipelineContracts.sha256(Files.readAllBytes(report));
		runScript("C6000ReviewPipelineSchedules.java",
			new String[] { manifest.toString(), report.toString(), "apply", digest });
		if (!enabled(absorber) || !enabled(retjump) ||
			!C6000PipelineContracts.recordedReview(currentProgram, retjump).entrySources().equals(List.of(source(retjump)))) {
			throw new AssertionError("apply must enable both with retjump's new review: " +
				C6000PipelineContracts.recordedReview(currentProgram, retjump));
		}
		checks++;
		try (var files = Files.newDirectoryStream(directory)) { for (Path file : files) Files.delete(file); }
		Files.delete(directory);
		println("C6000_WINDOW_NEIGHBOUR_BATCH_OK checks=" + checks);
	}

	private JsonArray report(Path manifest, Path report) throws Exception {
		runScript("C6000ReviewPipelineSchedules.java", new String[] { manifest.toString(), report.toString() });
		return JsonParser.parseString(Files.readString(report)).getAsJsonObject().getAsJsonArray("functions");
	}

	private static String status(JsonArray rows, int i) { return rows.get(i).getAsJsonObject().get("status").getAsString(); }

	private static String reason(JsonArray rows, int i) {
		var row = rows.get(i).getAsJsonObject();
		return row.has("reason") ? row.get("reason").getAsString() : "";
	}

	private boolean enabled(Function f) {
		return BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
			currentProgram.getRegister("c_schedule_entry"), f.getEntryPoint(), false));
	}

	private C6000PipelineContracts.SourceWindow window(long start) throws Exception {
		return new C6000PipelineContracts.SourceWindow(start, 32,
			C6000PipelineContracts.sha256(getBytes(toAddr(start), 32)));
	}

	private C6000PipelineContracts.SourceWindow source(Function f) throws Exception {
		return window(f.getEntryPoint().getOffset() & ~31L);
	}

	private String manifest(Map<Function, List<C6000PipelineContracts.SourceWindow>> sources,
			Map<Function, String> evidence, Function... functions) {
		var plan = new JsonObject();
		plan.addProperty("schema", 1);
		plan.addProperty("language_id", currentProgram.getLanguageID().getIdAsString());
		var rows = new JsonArray();
		for (var f : functions) {
			var row = new JsonObject();
			row.addProperty("entry", f.getEntryPoint().getOffset());
			row.addProperty("drained_entry_evidence", evidence.getOrDefault(f, EVIDENCE));
			row.add("previous_e1_writes", new JsonArray());
			row.add("entry_sources", new Gson().toJsonTree(sources.get(f)));
			rows.add(row);
		}
		plan.add("functions", rows);
		return plan.toString();
	}
}
