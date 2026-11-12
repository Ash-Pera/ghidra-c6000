// SPDX-License-Identifier: Apache-2.0
package c6000;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Drop the data reference Ghidra's scalar analysis puts on an MVK/MVKL whose
 * register an MVKH completes before anything reads it (SPRUFE8B MVK, MVKL,
 * MVKH): the register never holds the low half's address. A return address
 * built in a call's delay slots is the usual case; the stray reference makes
 * the address look like an entry into whatever code sits there.
 */
public class C6000LowHalfReferenceAnalyzer extends AbstractAnalyzer {
	public C6000LowHalfReferenceAnalyzer() {
		super("C6000 Low-Half References",
			"Removes the data reference of an MVK/MVKL low half that an MVKH completes to another value",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		var references = program.getReferenceManager();
		int dropped = 0;
		for (Instruction insn : program.getListing().getInstructions(set, true)) {
			monitor.checkCancelled();
			String name = op(insn);
			if (!name.equals("MVK") && !name.equals("MVKL")) continue;
			var scalar = insn.getScalar(0);
			Register dst = insn.getRegister(1);
			if (scalar == null || dst == null) continue;
			long low = scalar.getSignedValue() & 0xffffffffL;
			Long full = completed(program, insn, dst, low);
			if (full == null || full == low) continue;
			for (Reference r : references.getReferencesFrom(insn.getAddress())) {
				if (r.getSource() == SourceType.ANALYSIS && r.getReferenceType().isData() &&
						r.getToAddress().getOffset() == low) {
					references.delete(r);
					dropped++;
				}
			}
		}
		if (dropped > 0) log.appendMsg(getName(), "dropped " + dropped + " MVK low-half reference(s)");
		return true;
	}

	/**
	 * The value an unpredicated MVKH within the next five cycles gives dst, or
	 * null: nothing else writes dst, nothing reads it before the MVKH's write
	 * lands, and no earlier branch lands in between (SPRUFE8B 3.5, 4.2.6).
	 */
	private static Long completed(Program program, Instruction mvk, Register dst, long low) {
		try {
			var listing = program.getListing();
			// The MVK's own packet: another writer of dst there is a conflict.
			Instruction first = mvk;
			int span = 1;
			for (var at : C6000ExecutionPackets.issuePrefix(program, mvk.getAddress())) {
				var prior = listing.getInstructionAt(at);
				if (prior == null || writes(prior, dst)) return null;
				if (prior.getAddress().compareTo(first.getAddress()) < 0) first = prior;
				span = Math.max(span, cycles(prior));
			}
			Instruction cur = mvk;
			while (C6000ExecutionPackets.parallelWithNext(program, cur)) {
				cur = next(program, cur);
				if (cur == null || writes(cur, dst)) return null;
				span = Math.max(span, cycles(cur));
			}
			// Later packets, each read before any write of this cycle lands.
			int cycle = 0;
			Long result = null;
			while (result == null) {
				cycle += span;
				if (cycle > 5) return null;
				cur = next(program, cur);
				if (cur == null) return null;
				span = 1;
				while (true) {
					// MVKH keeps dst's low half: its own read is the completion.
					if (op(cur).equals("MVKH") && dst.equals(cur.getRegister(1)) &&
							!cur.getMnemonicString().contains("[") && result == null) {
						var high = cur.getScalar(0);
						if (high == null) return null;
						// The operand is the high half itself, or (as dis6x prints it) already shifted.
						long h = high.getUnsignedValue();
						result = ((h > 0xffffL ? h >>> 16 : h) & 0xffffL) << 16 | (low & 0xffffL);
					}
					else if (reads(cur, dst) || writes(cur, dst)) return null;
					span = Math.max(span, cycles(cur));
					if (!C6000ExecutionPackets.parallelWithNext(program, cur)) break;
					cur = next(program, cur);
					if (cur == null) return null;
				}
			}
			return landsBefore(program, first, cycle) ? null : result;
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	/**
	 * A branch issued in the five cycles before the packet at first (cycle 0)
	 * may land by cycle limit. The walk stops at a function entry (a call
	 * leaves no branch pending); a gap or another incoming jump counts as one.
	 */
	private static boolean landsBefore(Program program, Instruction first, int limit)
			throws MemoryAccessException {
		var listing = program.getListing();
		int cycle = 0;
		Instruction start = first;
		while (true) {
			if (program.getFunctionManager().getFunctionAt(start.getAddress()) != null) return false;
			if (jumpedTo(program, start)) return true;
			if (cycle <= -5) return false;
			Instruction last = before(listing, start);
			if (last == null) return true;
			Instruction head = last;
			for (var b = before(listing, head); b != null && C6000ExecutionPackets.parallelWithNext(program, b);
					b = before(listing, head)) head = b;
			int span = 1;
			for (var i = head; i != null && i.getAddress().compareTo(last.getAddress()) <= 0; i = listing.getInstructionAfter(i.getAddress()))
				span = Math.max(span, cycles(i));
			cycle -= span;
			for (var i = head; i != null && i.getAddress().compareTo(last.getAddress()) <= 0; i = listing.getInstructionAfter(i.getAddress())) {
				String name = op(i);
				boolean branch = name.equals("B") || name.equals("BNOP") || name.equals("BDEC") ||
					name.equals("BPOS") || name.equals("CALLP") || i.getFlowType().isJump() || i.getFlowType().isCall();
				if (branch && cycle + 6 > 0 && cycle + 6 <= limit) return true;
			}
			start = head;
		}
	}

	/** The contiguous instruction before i, or null. */
	private static Instruction before(ghidra.program.model.listing.Listing listing, Instruction i) {
		var b = listing.getInstructionBefore(i.getAddress());
		return b != null && b.getMaxAddress().next().equals(i.getAddress()) ? b : null;
	}

	/** Some jump or call (not a fall-through) lands on i. */
	private static boolean jumpedTo(Program program, Instruction i) {
		for (var r : program.getReferenceManager().getReferencesTo(i.getAddress()))
			if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough()) return true;
		return false;
	}

	/** Mnemonic without predicate, delay-slot mark or unit. */
	private static String op(Instruction i) {
		return C6000CallAnalyzer.baseName(i).split("\\.")[0];
	}

	private static Instruction next(Program program, Instruction cur) {
		var next = program.getListing().getInstructionAfter(cur.getAddress());
		// A fetch-packet header or a gap ends the straight line.
		return next != null && next.getMinAddress().equals(cur.getMaxAddress().next()) ? next : null;
	}

	private static int cycles(Instruction i) {
		if (!op(i).equals("NOP")) return 1;
		var n = i.getScalar(0);
		return n == null ? 1 : Math.max(1, (int) n.getValue());
	}

	private static boolean writes(Instruction i, Register r) {
		for (Object o : i.getResultObjects()) if (o instanceof Register w && overlaps(w, r)) return true;
		return false;
	}

	private static boolean reads(Instruction i, Register r) {
		for (Object o : i.getInputObjects()) if (o instanceof Register w && overlaps(w, r)) return true;
		return false;
	}

	private static boolean overlaps(Register a, Register b) {
		return a.equals(b) || a.contains(b) || b.contains(a);
	}
}
