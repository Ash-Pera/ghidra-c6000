// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.math.BigInteger;
import java.util.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Prove finite native delay windows, then expose them to SLEIGH in bytes.
 * SPRUFE8B 3.5, 3.10.2.3, 4.2.6; B/BNOP/CALLP execution descriptions.
 * This is control-flow scheduling, not a register-write latency model.
 */
public final class C6000DelaySlots {
    private static final int MAX_BYTES = 254;
    private static final int MAX_INSTRUCTIONS = 64;
    /** Bookmark category on a branch whose window relieveOverlaps released. */
    public static final String RELEASED = "C6000 Released Delay Window";
    private C6000DelaySlots() { }

    public record Repair(String branch, String end, int delayBytes, int oldDepth,
            int newDepth, long addedBodyBytes) { }
    private record SavedRef(Reference reference, boolean primary, long symbolId) { }
    private record SavedInstruction(Address at, FlowOverride override, String[] comments,
            List<SavedRef> references, boolean fallThroughOverridden, Address fallThrough) { }
    private record Window(Instruction branch, Address end, Function owner) { }

    /** B/BNOP or CALLP; nested transfers and ownership conflicts are refused. */
    public static List<Repair> recover(Program program, TaskMonitor monitor, MessageLog log)
            throws Exception {
        int transaction = program.startTransaction("Recover C6000 delay windows");
        try {
            List<Repair> result = recoverWindows(program, monitor, log);
            // A disassembler poll stops quietly: report its cancel.
            monitor.checkCancelled();
            return result;
        }
        finally {
            // Aborting a nested transaction aborts all of auto-analysis; a failed window is put back instead.
            program.endTransaction(transaction, true);
        }
    }

    private static List<Repair> recoverWindows(Program program, TaskMonitor monitor, MessageLog log)
            throws Exception {
        int quiet = inertJumps(program, monitor);
        if (quiet > 0) log.appendMsg("C6000 Delay Slots", "made " + quiet + " in-sequence jump(s) inert");
        List<Address[]> pairs = pairJumps(program, monitor);
        if (!pairs.isEmpty()) log.appendMsg("C6000 Delay Slots", "paired " + pairs.size() + " complementary jump(s)");
        Map<Address, C6000CallAnalyzer.Preemption> cuts = new HashMap<>();
        List<Repair> result = new ArrayList<>();
        int preempted = neutralise(program, cuts, result, monitor);
        if (preempted > 0) log.appendMsg("C6000 Delay Slots", "continued " + preempted + " preempted jump(s)");
        int carried = carryTails(program, monitor);
        if (carried > 0) log.appendMsg("C6000 Delay Slots", "carried " + carried + " shared call tail(s)");
        int arms = carryCallArms(program, monitor);
        if (arms > 0) log.appendMsg("C6000 Delay Slots", "carried " + arms + " call arm(s)");
        List<Address> candidates = new ArrayList<>(), stale = new ArrayList<>(), uncut = new ArrayList<>();
        var it = program.getListing().getInstructions(true);
        while (it.hasNext()) {
            var ins = it.next();
            String full = ins.getMnemonicString(), name = C6000CallAnalyzer.baseName(ins);
            if (full.startsWith("_") || flag(program, ins.getAddress(), "c_inert")) continue;
            if (!(name.equals("B.S1") || name.equals("B.S2") || name.equals("BNOP.S1") ||
                    name.equals("BNOP.S2") || name.equals("CALLP.S1") || name.equals("CALLP.S2"))) continue;
            var override = ins.getFlowOverride();
            // Issue #34: the SLEIGH captures a predicate and target before the
            // slots, so predicated and delayed-call displacement branches are
            // lifted correctly once their window is proven.
            // The register form also captures predicate and target first, so a
            // register call, jump or return gets its window too (SPRUFE8B 4.2.6, B; issue #70).
            boolean displacement = ins.getRegister(0) == null;
            boolean tail = override == FlowOverride.CALL_RETURN && !full.startsWith("[") && !name.startsWith("CALLP");
            if (full.startsWith("[") && !displacement && override != FlowOverride.CALL && !cuts.containsKey(ins.getAddress())) {
                // A return's window that no cut supports this pass is stale unless its full window is proven.
                boolean cut = preemptingTransfer(ins) &&
                    ins.getPrototype().getDelaySlotByteCount() > parallelBytes(program, ins.getAddress());
                if (override != FlowOverride.NONE && override != FlowOverride.RETURN) {
                    if (cut) stale.add(ins.getAddress());
                    continue;
                }
                if (cut) uncut.add(ins.getAddress());
            }
            if (override != FlowOverride.NONE && override != FlowOverride.RETURN &&
                    override != FlowOverride.CALL && !tail) continue;
            candidates.add(ins.getAddress());
        }
        for (Address at : stale) result.add(release(program, program.getListing().getInstructionAt(at)));
        Reader reader = new Reader(program, cuts);
        for (Address at : candidates) {
            monitor.checkCancelled();
            if (!lay(program, reader, at, cuts.get(at), result, monitor) && uncut.contains(at))
                result.add(release(program, program.getListing().getInstructionAt(at)));
        }
        // The complement's transfer is the window owner's not-taken path; without a window, undo it.
        for (Address[] pair : pairs) {
            Instruction x = program.getListing().getInstructionAt(pair[0]);
            if (x != null && x.getPrototype().getDelaySlotByteCount() > parallelBytes(program, pair[0])) {
                if (!pair[1].equals(x.getFallThrough())) x.setFallThrough(pair[1]);
            }
            else {
                Instruction y = program.getListing().getInstructionAt(pair[2]);
                if (y != null) setInert(program, y, false, monitor);
            }
        }
        // Windows lay() did not lay or confirm: the packet primer's parallel-peer windows, say.
        List<Instruction> windowed = new ArrayList<>();
        for (Instruction ins : program.getListing().getInstructions(true))
            if (ins.getPrototype().getDelaySlotByteCount() > 0) windowed.add(ins);
        for (Instruction ins : windowed) proveFallThrough(program, ins);
        if (!result.isEmpty()) Msg.info(C6000DelaySlots.class, "C6000 Delay Slots> recovered " + result.size() + " proven window(s)");
        return result;
    }

    /** Lay the branch's proven window, cut where preemption's jump lands if non-null; true once it is laid. */
    private static boolean lay(Program program, Reader reader, Address at,
            C6000CallAnalyzer.Preemption preemption, List<Repair> result, TaskMonitor monitor) throws Exception {
        Instruction branch = program.getListing().getInstructionAt(at);
        if (branch == null || branch.isInDelaySlot()) return false;
        // Issue #52: relieveOverlaps released this window for the decompiler.
        if (program.getBookmarkManager().getBookmark(at, BookmarkType.ANALYSIS, RELEASED) != null) return false;
        Window window = reader.window(branch, monitor, preemption);
        if (window == null) return false;
        int bytes = (int) (window.end().subtract(branch.getMaxAddress()));
        if (bytes == 0) return branch.getPrototype().getDelaySlotByteCount() == 0;
        // A tail call inherits B3; a B that sets B3 returns (SPRUFE8B 4.2.6, B, ADDKPC).
        if (branch.getFlowOverride() == FlowOverride.CALL_RETURN &&
                (setsLink(program, reader, branch, window.end()) ||
                    new C6000CallAnalyzer.Walker(program).recognize(branch) != null)) return false;
        BigInteger old = program.getProgramContext().getValue(
            program.getRegister("c_flow_delay"), at, false);
        boolean nativeReady = old != null && old.intValue() == bytes &&
            branch.getPrototype().getDelaySlotByteCount() == bytes;
        if (nativeReady) {
            var last = program.getListing().getInstructionContaining(window.end());
            nativeReady = last != null && last.isInDelaySlot();
        }
        // A delayed call returns after its window; the call analyzer's
        // fallthrough to the first slot predates the window.
        boolean delayedCall=branch.getFlowOverride()==FlowOverride.CALL &&
            branch.getMaxAddress().next().equals(branch.getFallThrough());
        if (!nativeReady) {
            if (!canMaterialize(program, window, bytes, monitor)) return false;
            result.add(apply(program, window, bytes));
        }
        else if (window.owner() != null && !window.owner().getBody().contains(window.end())) {
            var body = new AddressSet(window.owner().getBody());
            long before = body.getNumAddresses();body.add(at, window.end());
            window.owner().setBody(body);
            result.add(new Repair(at.toString(),window.end().toString(),bytes,
                branch.getDelaySlotDepth(),branch.getDelaySlotDepth(),body.getNumAddresses()-before));
        }
        // Ghidra's generic fallthrough calculator parses the slots with the
        // issue's context: wrong across mixed widths, and for big-endian
        // compact slots, whose halfword is context (issue #31). Keep the
        // proven next execute-packet address.
        Instruction now = program.getListing().getInstructionAt(at);
        boolean generic = now.getFlowType().hasFallthrough() && !now.isFallThroughOverridden();
        Address resume = resume(program, window.end());
        // A call's slots are laid: its callee returns where B3 points, which the hardware decides.
        if (delayedCall) {
            Address link = new C6000CallAnalyzer.Walker(program).returnPoint(now);
            if (link != null) resume = link;
        }
        if ((delayedCall || generic) && !resume.equals(now.getFallThrough())) {
            now.setFallThrough(resume);
            if(nativeReady)result.add(new Repair(at.toString(),window.end().toString(),bytes,
                branch.getDelaySlotDepth(),branch.getDelaySlotDepth(),0));
        }
        return true;
    }

    /**
     * Issue #52: release native windows that make a function undecompilable.
     * A jump from outside into a window's slots is legal: the hardware runs the
     * slots in sequence from there (SPRUFE8B 3.5, 4.2.6). The decompiler lifts a
     * branch and its native slots as one instruction, re-reads an entered window
     * with an "overlaps instruction" warning and still produces correct C, but
     * Ghidra 12.2 counts each overlap as bad data and abandons the function past
     * its limit (four by default). Decompile each function holding an entered
     * window; while it fails on an overlap, release the window the error names
     * and retry. Only those windows lose their delay-slot lifting.
     * @return the number of windows released
     */
    public static int relieveOverlaps(Program program, AddressSetView set, TaskMonitor monitor)
            throws Exception {
        var functions = program.getFunctionManager();
        Set<Function> candidates = new LinkedHashSet<>();
        for (Instruction branch : program.getListing().getInstructions(set, true)) {
            monitor.checkCancelled();
            int laid = branch.getPrototype().getDelaySlotByteCount();
            Address at = branch.getAddress();
            if (laid <= parallelBytes(program, at) || !entered(program, at, branch.getMaxAddress().add(laid))) continue;
            // The decompiler follows flow past a stale body: also try the function before unowned code.
            Function owner = functions.getFunctionContaining(at);
            if (owner == null) {
                var before = functions.getFunctions(at, false);
                owner = before.hasNext() ? before.next() : null;
            }
            if (owner != null) candidates.add(owner);
        }
        if (candidates.isEmpty()) return 0;
        int released = 0;
        var decompiler = new ghidra.app.decompiler.DecompInterface();
        // Default options: the CodeBrowser's bad-data limit is not a tool option.
        decompiler.setOptions(new ghidra.app.decompiler.DecompileOptions());
        if (!decompiler.openProgram(program)) return 0;
        int transaction = program.startTransaction("Release C6000 delay windows for the decompiler");
        try {
            for (Function function : candidates) {
                for (int attempt = 0; attempt < MAX_INSTRUCTIONS && !function.isDeleted(); attempt++) {
                    monitor.checkCancelled();
                    var result = decompiler.decompileFunction(function, 60, monitor);
                    if (result == null || result.decompileCompleted()) break;
                    String error = result.getErrorMessage();
                    Instruction branch = overlapped(program, error);
                    // Other bad data (an unmapped target, say) can be the last straw:
                    // the function's own entered windows still count toward the limit.
                    if (branch == null && error != null && error.contains("Bad instruction count exceeded"))
                        branch = enteredIn(program, function);
                    if (branch == null) break;
                    Address at = branch.getAddress();
                    if (branch.getPrototype().getDelaySlotByteCount() <= parallelBytes(program, at)) break;
                    // Entered only at NOP slots, which only idle (SPRUFE8B p. 388): end the window before them and keep every effect.
                    Address idle = idleTail(program, branch);
                    if (idle != null) release(program, branch, (int) idle.subtract(branch.getMaxAddress()) - 1);
                    else release(program, branch);
                    uncontinue(program, at);
                    Instruction now = program.getListing().getInstructionAt(at);
                    if (now != null) proveFallThrough(program, now);
                    decompiler.flushCache();
                    program.getBookmarkManager().setBookmark(at, BookmarkType.ANALYSIS, RELEASED,
                        (idle != null ? "Native delay window ended before its entered NOP slots at " + idle + ": "
                            : "Native delay window released: ") + function.getName() +
                        " exceeded the decompiler's overlapping-instruction limit (issue #52)");
                    released++;
                }
            }
            // A cancelled decompile only fails: report the cancel.
            monitor.checkCancelled();
        }
        finally {
            // Never abort: release puts a failed window back (see recover).
            program.endTransaction(transaction, true);
            decompiler.dispose();
        }
        if (released > 0) Msg.info(C6000DelaySlots.class, "C6000 Delay Slots> released " + released +
            " entered window(s) for the decompiler");
        return released;
    }

    private static final java.util.regex.Pattern OVERLAP = java.util.regex.Pattern.compile(
        "overlaps instruction at \\((\\w+),0x([0-9a-fA-F]+)\\)");

    /** The branch whose native window a decompiler "overlaps instruction" error names. */
    private static Instruction overlapped(Program program, String error) {
        var m = error == null ? null : OVERLAP.matcher(error);
        if (m == null || !m.find()) return null;
        var space = program.getAddressFactory().getAddressSpace(m.group(1));
        if (space == null) return null;
        return program.getListing().getInstructionAt(space.getAddress(Long.parseUnsignedLong(m.group(2), 16)));
    }

    /** The first branch in the function's body whose laid window is entered, or null. */
    private static Instruction enteredIn(Program program, Function function) {
        for (Instruction branch : program.getListing().getInstructions(function.getBody(), true)) {
            int laid = branch.getPrototype().getDelaySlotByteCount();
            Address at = branch.getAddress();
            if (laid > parallelBytes(program, at) && entered(program, at, branch.getMaxAddress().add(laid))) return branch;
        }
        return null;
    }

    /** First slot entered from outside the window when only NOPs follow to its end, else null. */
    private static Address idleTail(Program program, Instruction branch) {
        Address at = branch.getAddress(), end = branch.getMaxAddress().add(branch.getPrototype().getDelaySlotByteCount());
        Address first = firstEntry(program, at, end);
        if (first == null || first.compareTo(branch.getMaxAddress().add(parallelBytes(program, at))) <= 0) return null;
        var listing = program.getListing();
        for (Address cursor = first; cursor.compareTo(end) <= 0;) {
            Instruction slot = listing.getInstructionAt(cursor);
            if (slot == null || !C6000CallAnalyzer.baseName(slot).equals("NOP")) return null;
            cursor = slot.getMaxAddress().next();
        }
        return first;
    }

    /** Control from outside [at, end] reaches one of the slots after at. */
    private static boolean entered(Program program, Address at, Address end) {
        return firstEntry(program, at, end) != null;
    }

    /** The lowest slot after at that control from outside [at, end] reaches, or null. */
    private static Address firstEntry(Program program, Address at, Address end) {
        var references = program.getReferenceManager();
        var targets = references.getReferenceDestinationIterator(new AddressSet(at.next(), end), true);
        while (targets.hasNext()) {
            Address target = targets.next();
            for (var it = references.getReferencesTo(target); it.hasNext();) {
                Reference r = it.next();
                Address from = r.getFromAddress();
                if (r.getReferenceType().isFlow() && (from.compareTo(at) < 0 || from.compareTo(end) > 0)) return target;
            }
        }
        return null;
    }

    /** A return through B3. */
    static boolean preemptingTransfer(Instruction transfer) {
        var register = transfer.getRegister(0);
        var override = transfer.getFlowOverride();
        return register != null && register.getName().equals("B3") && !transfer.getFlowType().isCall() &&
            override != FlowOverride.CALL && override != FlowOverride.CALL_RETURN;
    }

    /** Whether the jump's branch is overridden to continue (see neutralise). */
    static boolean continues(Program program, Instruction jump) {
        for (Reference r : program.getReferenceManager().getReferencesFrom(jump.getAddress())) {
            if (r.getReferenceType() == RefType.JUMP_OVERRIDE_UNCONDITIONAL && r.isPrimary()) return true;
        }
        return false;
    }

    /** Bytes of the branch's own execute packet after it: the primer's c_flow_delay (C6000PacketContext). */
    private static int parallelBytes(Program program, Address at) {
        try { return C6000ExecutionPackets.parallelBytes(program, at); }
        catch (MemoryAccessException e) { return 0; }
    }

    /**
     * Undo apply(): the slots become ordinary instructions again, lifted after
     * the transfer as before issues #34 and #48. Keep the branch's override, the
     * slots' annotations and every reference.
     */
    private static Repair release(Program p, Instruction original) throws Exception {
        return release(p, original, parallelBytes(p, original.getAddress()));
    }

    /** As above, but the first keep bytes after the branch stay in its window. */
    private static Repair release(Program p, Instruction original, int keep) throws Exception {
        var listing = p.getListing();
        Address at = original.getAddress();
        Address end = original.getMaxAddress().add(original.getPrototype().getDelaySlotByteCount());
        int oldDepth = original.getDelaySlotDepth();
        FlowOverride override = original.getFlowOverride();
        List<SavedInstruction> saved = snapshot(p, at, end);
        var undo = Undo.of(p, at, end, override, saved);
        listing.clearCodeUnits(at, end, false);
        try {
            p.getProgramContext().setValue(p.getRegister("c_flow_delay"), at, at, BigInteger.valueOf(keep));
            // Never polled: a cancel here would leave the window half decoded.
            Disassembler disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null);
            // A terminal branch has no fall-through: decode each released slot run too.
            for (Address cursor = at; cursor.compareTo(end) <= 0;) {
                if (listing.getInstructionContaining(cursor) == null)
                    disassembler.disassemble(cursor, new AddressSet(cursor, end), false);
                var ins = listing.getInstructionContaining(cursor);
                if (ins == null) throw new IllegalStateException("Could not re-decode released window at " + cursor);
                cursor = ins.getMaxAddress().next();
            }
            var branch = listing.getInstructionAt(at);
            if (branch == null || branch.getPrototype().getDelaySlotByteCount() != keep)
                throw new IllegalStateException("Could not release native delay window at " + at + ": " + branch);
            branch.setFlowOverride(override);
            // The fall-through past the window belonged to the window; any other override stays.
            restore(p, at, saved, false, resume(p, end));
            return new Repair(at.toString(), end.toString(), keep, oldDepth, branch.getDelaySlotDepth(), 0);
        }
        catch (Exception failure) {
            throw undo.putBack(failure);
        }
    }

    /**
     * Ghidra's generic fall-through re-parses the slots with the issue's context, so it is wrong
     * across mixed widths and for big-endian compact slots (issue #31; Ghidra #10242). Give a
     * windowed conditional jump with no fall-through override the next execute packet after its
     * native window. Returns whether it changed.
     */
    private static boolean proveFallThrough(Program p, Instruction ins) {
        int bytes = ins.getPrototype().getDelaySlotByteCount();
        if (bytes == 0 || !ins.getFlowType().isJump() || !ins.getFlowType().hasFallthrough()) return false;
        Address end, resume;
        try { end = ins.getMaxAddress().add(bytes); resume = resume(p, end); }
        catch (AddressOutOfBoundsException e) { return false; }
        boolean changed = false;
        if (!ins.isFallThroughOverridden() && !resume.equals(ins.getFallThrough())) {
            ins.setFallThrough(resume);
            changed = true;
        }
        if (!resume.equals(ins.getFallThrough())) return changed;
        // Ghidra's body walk (FollowFlow) counts slots with the same generic parse and can drop the
        // tail of the window once the fall-through skips it: keep the window, as lay() does.
        Function owner = p.getFunctionManager().getFunctionContaining(ins.getAddress());
        if (owner != null && !owner.getBody().contains(ins.getAddress(), end)) {
            var body = new AddressSet(owner.getBody());
            body.add(ins.getAddress(), end);
            try { owner.setBody(body); }
            catch (ghidra.program.database.function.OverlappingFunctionException e) { }
        }
        return changed;
    }

    /** The next execute packet after a window ending at end: past a fetch-packet header (SPRUFE8B 3.10.2). */
    private static Address resume(Program program, Address end) {
        Address next = end.next();
        try {
            if ((next.getOffset() & 31) == 28 && (program.getMemory().getInt(next) >>> 28) == 0xe) return next.add(4);
        }
        catch (MemoryAccessException | AddressOutOfBoundsException e) { }
        return next;
    }

    /**
     * A jump whose target only idles until a return issued in its
     * window lands (C6000CallAnalyzer.Preemption) leaves nothing to its target:
     * execution goes on through its window. Override its branch to its own
     * fall-through and drop the edge to the target, whose NOPs are usually
     * another return's delay slots. The return's window then ends where the
     * jump lands (Reader.window), so the jump is continued only once that
     * shortened window is laid; only the window's code is decoded before. An analysis
     * override whose preemption no longer holds is removed. Fills cuts with
     * the return of every continued jump; recoverWindows releases a predicated
     * return's window that no cut supports any more.
     * @return the number of jumps continued or restored
     */
    private static int neutralise(Program program, Map<Address, C6000CallAnalyzer.Preemption> cuts,
            List<Repair> result, TaskMonitor monitor) throws Exception {
        var listing = program.getListing();
        var references = program.getReferenceManager();
        var walker = new C6000CallAnalyzer.Walker(program);
        var reader = new Reader(program, Map.of());
        List<Address> jumps = new ArrayList<>();
        for (var it = listing.getInstructions(true); it.hasNext();) {
            var ins = it.next();
            if (C6000CallAnalyzer.Walker.displacementJump(ins)) jumps.add(ins.getAddress());
        }
        Disassembler disassembler = null;
        int count = 0;
        for (Address at : jumps) {
            monitor.checkCancelled();
            // Disassembly below can change the listing the list was taken from.
            Instruction jump = listing.getInstructionAt(at);
            if (jump == null || !C6000CallAnalyzer.Walker.displacementJump(jump)) continue;
            Address target = jump.getDefaultFlows()[0];
            Address next = jump.getMaxAddress().next().add(jump.getPrototype().getDelaySlotByteCount());
            Reference ours = null;
            boolean overridden = false, other = false;
            for (Reference r : references.getReferencesFrom(at)) {
                if (r.getReferenceType() != RefType.JUMP_OVERRIDE_UNCONDITIONAL) continue;
                if (r.getToAddress().equals(next) && r.isPrimary()) {
                    overridden = true;
                    if (r.getSource() == SourceType.ANALYSIS) ours = r;
                }
                else other = true;
            }
            // Someone else's override stands.
            if (other) continue;
            var preemption = walker.preemption(jump);
            boolean proven = preemption != null && preemption.exact() && preemptingTransfer(preemption.transfer()) &&
                reader.window(preemption.transfer(), monitor, preemption) != null;
            boolean changed = false;
            if (proven && listing.getInstructionAt(next) == null) {
                if (disassembler == null) disassembler = Disassembler.getDisassembler(program, monitor, null);
                disassembler.disassemble(next, null, true);
                changed = true;
            }
            // Proven is not laid: lay the return's cut window before the jump continues.
            proven = proven && lay(program, reader, preemption.transfer().getAddress(), preemption, result, monitor);
            if (!proven) {
                if (ours != null) {
                    restoreJump(program, jump, ours, target);
                    count++;
                }
                continue;
            }
            cuts.put(preemption.transfer().getAddress(), preemption);
            for (Reference r : references.getReferencesFrom(at)) {
                if (r.getReferenceType().isFlow() && !r.getReferenceType().isOverride() && r.getToAddress().equals(target)) {
                    references.delete(r);
                    changed = true;
                }
            }
            if (!overridden) {
                var r = references.addMemoryReference(at, next, RefType.JUMP_OVERRIDE_UNCONDITIONAL,
                    SourceType.ANALYSIS, 0);
                references.setPrimary(r, true);
                changed = true;
            }
            if (!changed) continue;
            count++;
            // The window runs after the jump on every path: the jump's function owns it.
            // Extend the body only; recomputing it from flow could absorb a later entry.
            Function owner = program.getFunctionManager().getFunctionContaining(at);
            var window = new AddressSet(next, preemption.windowEnd());
            if (owner != null && !owner.getBody().contains(window)) {
                boolean free = true;
                for (var it = program.getFunctionManager().getFunctionsOverlapping(window); it.hasNext();)
                    if (!it.next().equals(owner)) free = false;
                if (free) {
                    try { owner.setBody(new AddressSet(owner.getBody()).union(window)); }
                    catch (ghidra.program.database.function.OverlappingFunctionException e) { }
                }
            }
        }
        return count;
    }

    /** Give each jump continued on the released return at at (neutralise) its target back. */
    private static void uncontinue(Program program, Address at) {
        var walker = new C6000CallAnalyzer.Walker(program);
        for (int i = 1; i <= C6000CallAnalyzer.MAX_WINDOW && at.getOffset() >= 4L * i; i++) {
            Instruction jump = program.getListing().getInstructionAt(at.subtract(4L * i));
            if (jump == null || !C6000CallAnalyzer.Walker.displacementJump(jump)) continue;
            for (Reference r : program.getReferenceManager().getReferencesFrom(jump.getAddress())) {
                if (r.getReferenceType() != RefType.JUMP_OVERRIDE_UNCONDITIONAL || !r.isPrimary() ||
                        r.getSource() != SourceType.ANALYSIS) continue;
                var preemption = walker.preemption(jump);
                if (preemption != null && preemption.transfer().getAddress().equals(at))
                    restoreJump(program, jump, r, jump.getDefaultFlows()[0]);
                break;
            }
        }
    }

    /**
     * Local: a displacement B that lands on the execute packet sequential issue
     * reaches in that cycle, issued with no other branch pending, transfers
     * nowhere: execution runs on in sequence either way (SPRUFE8B 3.5, 4.2.6 B;
     * DSP/BIOS issues such branches to hold off interrupts). Make it inert
     * (c_inert), so the packets it seemed to skip are lifted and the windows
     * holding it can be proven. Repeats until no further jump qualifies.
     */
    private static int inertJumps(Program program, TaskMonitor monitor) throws Exception {
        var listing = program.getListing();
        int count = 0;
        for (boolean again = true; again;) {
            again = false;
            List<Address> found = new ArrayList<>();
            Reader reader = new Reader(program);
            for (var it = listing.getInstructions(true); it.hasNext();) {
                var ins = it.next();
                monitor.checkCancelled();
                if (reader.inSequence(ins, monitor)) found.add(ins.getAddress());
            }
            for (Address at : found) {
                Instruction jump = listing.getInstructionAt(at);
                // An earlier jump made inert changed the listing: prove this one again.
                if (jump == null || !new Reader(program).inSequence(jump, monitor)) continue;
                Address landing = jump.getDefaultFlows()[0];
                Address end = setInert(program, jump, true, monitor);
                Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
                // The packets it seemed to skip: decode them in sequence.
                Address gap = end.next();
                while (listing.getInstructionAt(gap) != null && gap.compareTo(landing) < 0) gap = listing.getInstructionAt(gap).getMaxAddress().next();
                if (listing.getInstructionContaining(gap) == null) disassembler.disassemble(gap, null, true);
                // The packets it skipped run on every path through it: its function owns them.
                Function owner = program.getFunctionManager().getFunctionContaining(at);
                var span = new AddressSet(at, landing.previous());
                if (owner != null && !owner.getBody().contains(span)) {
                    boolean free = true;
                    for (var f = program.getFunctionManager().getFunctionsOverlapping(span); f.hasNext();)
                        if (!f.next().equals(owner)) free = false;
                    if (free) {
                        try { owner.setBody(new AddressSet(owner.getBody()).union(span)); }
                        catch (ghidra.program.database.function.OverlappingFunctionException e) { }
                    }
                }
                count++;
                again = true;
            }
        }
        return count;
    }

    /**
     * Local: two branches in one execute packet on complementary predicates of
     * one register land in the same cycle after the same window (SPRUFE8B 3.5,
     * 4.2.6 B). When one is a displacement B and the other's window can be
     * proven with it as an ordinary companion, the B becomes inert and, once the
     * window is recovered, the other's not-taken fall-through is its target.
     * @return {owner, target, inert B} per pair
     */
    private static List<Address[]> pairJumps(Program program, TaskMonitor monitor) throws Exception {
        var listing = program.getListing();
        List<Address[]> pairs = new ArrayList<>();
        List<Instruction[]> found = new ArrayList<>();
        Reader reader = new Reader(program);
        for (var it = listing.getInstructions(true); it.hasNext();) {
            var y = it.next();
            monitor.checkCancelled();
            Instruction x = reader.complement(y);
            if (x == null) continue;
            reader.ignore = y.getAddress();
            Window w = reader.window(x, monitor);
            reader.ignore = null;
            if (w != null && w.end().compareTo(x.getMaxAddress()) > 0) found.add(new Instruction[] { x, y });
        }
        for (var pair : found) {
            Address target = pair[1].getDefaultFlows()[0];
            setInert(program, pair[1], true, monitor);
            pairs.add(new Address[] { pair[0].getAddress(), target, pair[1].getAddress() });
        }
        return pairs;
    }

    /** Re-decode a branch with c_inert set or cleared, with any packet companion that lays it as a slot; the end of the re-decoded range. */
    private static Address setInert(Program program, Instruction jump, boolean on, TaskMonitor monitor) throws Exception {
        var listing = program.getListing();
        Address at = jump.getAddress();
        Address end = jump.getMaxAddress().add(jump.getPrototype().getDelaySlotByteCount());
        Address start = at;
        for (Address prior : C6000ExecutionPackets.issuePrefix(program, at)) {
            Instruction q = listing.getInstructionAt(prior);
            int laid = q == null ? 0 : q.getPrototype().getDelaySlotByteCount();
            if (laid > 0 && q.getMaxAddress().add(laid).compareTo(at) >= 0) {
                start = prior;
                if (q.getMaxAddress().add(laid).compareTo(end) > 0) end = q.getMaxAddress().add(laid);
                break;
            }
        }
        List<SavedInstruction> saved = snapshot(program, start, end);
        listing.clearCodeUnits(start, end, false);
        program.getProgramContext().setValue(program.getRegister("c_flow_delay"), at, at, BigInteger.ZERO);
        program.getProgramContext().setValue(program.getRegister("c_inert"), at, at, on ? BigInteger.ONE : BigInteger.ZERO);
        Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
        for (Address cursor = start; cursor.compareTo(end) <= 0;) {
            if (listing.getInstructionContaining(cursor) == null)
                disassembler.disassemble(cursor, new AddressSet(cursor, end), false);
            var ins = listing.getInstructionContaining(cursor);
            if (ins == null) throw new IllegalStateException("Could not re-decode branch at " + cursor);
            cursor = ins.getMaxAddress().next();
        }
        restore(program, at, saved, on, saved.get((int) at.subtract(start)).fallThrough());
        return end;
    }

    /** Whether the context field (c_inert, c_carry) is set at at. */
    static boolean flag(Program program, Address at, String field) {
        BigInteger v = program.getProgramContext().getValue(program.getRegister(field), at, false);
        return v != null && v.signum() != 0;
    }

    /**
     * Local: a jump into the last cycles of a call's window, with a call to the
     * same function and link issued in its own window and taken exactly when
     * the jump is (C6000CallAnalyzer.SharedTail), runs the tail and then that
     * call: the compiler shares one call tail between two call sites (SPRUFE8B
     * 3.5, 4.2.6 B). No native window can lift both, so the tail's last
     * instruction carries the call (c_carry, target by reference) and both
     * issuing branches stop transferring (c_inert). The owning call must be
     * unconditional and every other entry into its window refused.
     */
    private static int carryTails(Program program, TaskMonitor monitor) throws Exception {
        var listing = program.getListing();
        var walker = new C6000CallAnalyzer.Walker(program);
        var reader = new Reader(program);
        Map<Address, List<C6000CallAnalyzer.SharedTail>> tails = new LinkedHashMap<>();
        for (var it = listing.getInstructions(true); it.hasNext();) {
            var jump = it.next();
            monitor.checkCancelled();
            if (!C6000CallAnalyzer.Walker.displacementJump(jump) || continues(program, jump)) continue;
            var tail = walker.sharedTail(jump);
            if (tail != null && jump.getPrototype().getDelaySlotByteCount() <= parallelBytes(program, jump.getAddress()) && !tail.transfer().isInDelaySlot() && !flag(program, tail.last(), "c_carry")) tails.computeIfAbsent(tail.last(), k -> new ArrayList<>()).add(tail);
        }
        int count = 0;
        for (var entry : tails.entrySet()) {
            monitor.checkCancelled();
            var group = entry.getValue();
            Address tailStart = group.get(0).tail(), callee = group.get(0).callee();
            Instruction owner = tailOwner(program, reader, walker, group.get(0), monitor);
            if (owner == null) continue;
            boolean same = true;
            for (var t : group) same &= t.tail().equals(tailStart) && t.callee().equals(callee);
            if (!same || !onlyEntries(program, owner, entry.getKey(), group)) continue;
            Address last = entry.getKey();
            Address end = owner.getMaxAddress().add(owner.getPrototype().getDelaySlotByteCount());
            // Clearing a branch clears its laid slots (packet companions included): re-decode them with it.
            List<Address[]> transfers = new ArrayList<>();
            for (var t : group) transfers.add(new Address[] { t.transfer().getAddress(),
                t.transfer().getMaxAddress().add(t.transfer().getPrototype().getDelaySlotByteCount()) });
            redecode(program, owner.getAddress(), end, "c_inert", monitor);
            for (var range : transfers) redecode(program, range[0], range[1], "c_inert", monitor);
            Instruction carrier = listing.getInstructionAt(last);
            if (carrier == null) throw new IllegalStateException("shared tail lost its last instruction at " + last);
            redecode(program, last, carrier.getMaxAddress(), "c_carry", monitor);
            var r = program.getReferenceManager().addMemoryReference(last, callee, RefType.CALL_OVERRIDE_UNCONDITIONAL,
                SourceType.ANALYSIS, Reference.MNEMONIC);
            program.getReferenceManager().setPrimary(r, true);
            count++;
        }
        return count;
    }

    /**
     * Local: a predicated jump with a call issued in its window under the
     * opposite predicate of the same unchanged register (C6000CallAnalyzer.CallArm)
     * transfers exactly one way (SPRUFE8B 3.5, 4.2.6 B). The call's window
     * outlasts the jump's, so no native window lifts both: the call stops
     * transferring (c_inert), the jump takes its whole window, and the call's
     * last slot, reached only on the jump's fall-through, carries the call
     * (c_carry, target by reference). No other flow may enter either window.
     */
    private static int carryCallArms(Program program, TaskMonitor monitor) throws Exception {
        var listing = program.getListing();
        var functions = program.getFunctionManager();
        var walker = new C6000CallAnalyzer.Walker(program);
        var reader = new Reader(program);
        List<C6000CallAnalyzer.CallArm> arms = new ArrayList<>();
        for (var it = listing.getInstructions(true); it.hasNext();) {
            var jump = it.next();
            monitor.checkCancelled();
            if (!C6000CallAnalyzer.Walker.displacementJump(jump) || continues(program, jump) ||
                jump.getPrototype().getDelaySlotByteCount() > parallelBytes(program, jump.getAddress())) continue;
            var arm = walker.callArm(jump);
            if (arm != null) arms.add(arm);
        }
        int count = 0;
        for (var arm : arms) {
            monitor.checkCancelled();
            Instruction jump = listing.getInstructionAt(arm.jump().getAddress());
            Instruction call = listing.getInstructionAt(arm.call().getAddress());
            Instruction last = listing.getInstructionAt(arm.last());
            if (jump == null || call == null || last == null || jump.isInDelaySlot() || call.isInDelaySlot() ||
                flag(program, call.getAddress(), "c_inert") || flag(program, arm.last(), "c_carry")) continue;
            Function owner = functions.getFunctionContaining(jump.getAddress());
            if (!java.util.Objects.equals(owner, functions.getFunctionContaining(call.getAddress())) ||
                !java.util.Objects.equals(owner, functions.getFunctionContaining(arm.last())) ||
                entered(program, jump.getAddress(), last.getMaxAddress())) continue;
            // The jump's native window must hold the call, once inert, and end where the walker's does.
            Window w = reader.window(jump, monitor, call.getAddress());
            if (w == null || !w.end().equals(arm.jumpEnd())) continue;
            Address end = call.getMaxAddress().add(call.getPrototype().getDelaySlotByteCount());
            redecode(program, call.getAddress(), end, "c_inert", monitor);
            Instruction carrier = listing.getInstructionAt(arm.last());
            if (carrier == null) throw new IllegalStateException("call arm lost its last slot at " + arm.last());
            redecode(program, arm.last(), carrier.getMaxAddress(), "c_carry", monitor);
            var r = program.getReferenceManager().addMemoryReference(arm.last(), arm.callee(),
                RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
            program.getReferenceManager().setPrimary(r, true);
            // Ghidra counts the jump's slots by parsing them in the jump's context: there the call must parse inert too.
            jump = listing.getInstructionAt(arm.jump().getAddress());
            redecode(program, jump.getAddress(), jump.getMaxAddress().add(jump.getPrototype().getDelaySlotByteCount()), "c_arm",
                jump.getMnemonicString().startsWith("[!") ? 2 : 1, monitor);
            count++;
        }
        return count;
    }

    /** The unconditional call whose window ends at the tail's last instruction, to the same callee and link, or null. */
    private static Instruction tailOwner(Program program, Reader reader, C6000CallAnalyzer.Walker walker,
            C6000CallAnalyzer.SharedTail tail, TaskMonitor monitor) throws CancelledException {
        Instruction last = program.getListing().getInstructionAt(tail.last());
        if (last == null) return null;
        for (int back = 4; back <= MAX_BYTES; back += 4) {
            Instruction d = program.getListing().getInstructionAt(tail.tail().subtract(back));
            if (d == null || d.isInDelaySlot() || flag(program, d.getAddress(), "c_inert")) continue;
            String name = C6000CallAnalyzer.baseName(d);
            if (!(name.equals("B.S1") || name.equals("B.S2")) || d.getRegister(0) != null || d.getLength() != 4 ||
                d.getMnemonicString().startsWith("[")) continue;
            if (d.getDefaultFlows().length != 1 || !d.getDefaultFlows()[0].equals(tail.callee())) continue;
            Window w = reader.window(d, monitor);
            if (w == null || !w.end().equals(last.getMaxAddress())) continue;
            if (walker.recognize(d) == null || !resume(program, w.end()).equals(tail.landing())) continue;
            return d;
        }
        return null;
    }

    /** No flow enters the owner's slots except the group's jumps, at the tail's start. */
    private static boolean onlyEntries(Program program, Instruction owner, Address last,
            List<C6000CallAnalyzer.SharedTail> group) {
        Set<Address> jumps = new HashSet<>();
        for (var t : group) jumps.add(t.jump().getAddress());
        Instruction tailEnd = program.getListing().getInstructionAt(last);
        var refs = program.getReferenceManager();
        for (var to = refs.getReferenceDestinationIterator(new AddressSet(owner.getMaxAddress().next(), tailEnd.getMaxAddress()), true); to.hasNext();) {
            Address at = to.next();
            for (var it = refs.getReferencesTo(at); it.hasNext();) {
                Reference r = it.next();
                if (!r.getReferenceType().isFlow()) continue;
                Address from = r.getFromAddress();
                if (from.compareTo(owner.getAddress()) >= 0 && from.compareTo(tailEnd.getMaxAddress()) <= 0) continue;
                if (!jumps.contains(from) || !at.equals(group.get(0).tail())) return false;
            }
        }
        return true;
    }

    /** Re-decode [at, end] with the context field set at at; a branch made inert keeps no flow references. */
    private static void redecode(Program p, Address at, Address end, String field, TaskMonitor monitor) throws Exception {
        redecode(p, at, end, field, 1, monitor);
    }

    /** Re-decode [at, end] with the context field set to value at at. */
    private static void redecode(Program p, Address at, Address end, String field, long value, TaskMonitor monitor) throws Exception {
        List<SavedInstruction> saved = snapshot(p, at, end);
        p.getListing().clearCodeUnits(at, end, false);
        p.getProgramContext().setValue(p.getRegister("c_flow_delay"), at, at, BigInteger.ZERO);
        p.getProgramContext().setValue(p.getRegister(field), at, at, BigInteger.valueOf(value));
        Disassembler disassembler = Disassembler.getDisassembler(p, monitor, null);
        for (Address cursor = at; cursor.compareTo(end) <= 0;) {
            if (p.getListing().getInstructionContaining(cursor) == null)
                disassembler.disassemble(cursor, new AddressSet(cursor, end), false);
            var ins = p.getListing().getInstructionContaining(cursor);
            if (ins == null) throw new IllegalStateException("Could not re-decode shared call tail at " + cursor);
            cursor = ins.getMaxAddress().next();
        }
        // The issuing branch's own fall-through override went with its window.
        restore(p, at, saved, true, saved.get(0).fallThrough());
    }

    /**
     * Undo neutralise for a jump whose preemption no longer holds: drop our
     * override and restore the edge to its target. The return's cut window is
     * released or recomputed by the recovery that follows.
     */
    private static void restoreJump(Program program, Instruction jump, Reference ours, Address target) {
        var references = program.getReferenceManager();
        references.delete(ours);
        for (Reference r : references.getReferencesFrom(jump.getAddress()))
            if (r.getReferenceType().isFlow() && r.getToAddress().equals(target)) return;
        references.addMemoryReference(jump.getAddress(), target, jump.getFlowType(), SourceType.DEFAULT, 0);
    }

    /** Last byte of a branch's proven delay window, or null when it is not proven. */
    static Address windowEnd(Program program, Instruction branch, TaskMonitor monitor)
            throws CancelledException {
        Window window = new Reader(program).window(branch, monitor);
        return window == null ? null : window.end();
    }

    /** Whether the branch's packet or window writes B3 other than by a load restoring it. */
    private static boolean setsLink(Program p, Reader reader, Instruction branch, Address end) {
        var b3 = p.getRegister("B3");
        List<Instruction> packet = new ArrayList<>();
        try {
            for (Address at : C6000ExecutionPackets.issuePrefix(p, branch.getAddress())) packet.add(reader.decode(at));
        }
        catch (MemoryAccessException e) {
            return true;
        }
        for (Instruction i = reader.next(branch); i != null && i.getMinAddress().compareTo(end) <= 0; i = reader.next(i)) {
            packet.add(i);
        }
        for (Instruction i : packet) {
            if (i == null) return true;
            if (C6000CallAnalyzer.baseName(i).startsWith("LD")) continue;
            for (Object o : C6000PacketContext.architecturalResults(p, i)) {
                if (o instanceof ghidra.program.model.lang.Register r && r.contains(b3)) return true;
            }
        }
        return false;
    }

    /** Dry-run native parsing with the proposed context before removing any code units. */
    private static boolean canMaterialize(Program p, Window window, int bytes, TaskMonitor monitor) {
        Instruction issue = window.branch();
        Address at = issue.getAddress();
        var base = p.getLanguage().getContextBaseRegister();
        RegisterValue context = p.getProgramContext().getRegisterValue(base, at);
        if (context == null) context = new RegisterValue(base);
        context = context.combineValues(new RegisterValue(p.getRegister("c_flow_delay"),
            BigInteger.valueOf(bytes)));
        if (issue.getRegister(0) != null && !issue.getMnemonicString().startsWith("CALLP")) {
            context = context.combineValues(new RegisterValue(p.getRegister("c_branch_terminal"),
                BigInteger.ONE));
        }
        var disassembler = Disassembler.getDisassembler(p, monitor, null);
        // The pseudo parser's default argument cannot override stored context.
        // Supply an explicit future seed without writing the ProgramContext.
        var seed = new ghidra.program.disassemble.DisassemblerContextImpl(p.getProgramContext());
        seed.setFutureRegisterValue(at, context);
        disassembler.setSeedContext(seed);
        var block = disassembler.pseudoDisassembleBlock(
            new ghidra.program.model.mem.DumbMemBufferImpl(p.getMemory(), at), context, 1);
        if (block == null) return false;
        var branch = block.getInstructionAt(at);
        var tail = block.findFirstIntersectingInstruction(window.end(), window.end());
        return branch != null && branch.getPrototype().getDelaySlotByteCount() == bytes &&
            tail != null && tail.isInDelaySlot() && tail.getMaxAddress().equals(window.end());
    }

    private static Repair apply(Program p, Window window, int bytes)
            throws Exception {
        var listing = p.getListing();var original = window.branch();
        Address at = original.getAddress();int oldDepth = original.getDelaySlotDepth();
        FlowOverride override = original.getFlowOverride();
        boolean registerBranch=original.getRegister(0)!=null && !original.getMnemonicString().startsWith("CALLP");
        // A shorter window than the native one releases the old slots too.
        Address end = window.end(), old = original.getMaxAddress().add(original.getPrototype().getDelaySlotByteCount());
        // A jump's fall-through proven for the old window (proveFallThrough) goes with it.
        Address oldResume = original.getFlowType().isJump() && original.getPrototype().getDelaySlotByteCount() > 0 ?
            resume(p, old) : null;
        if (old.compareTo(end) > 0) end = old;
        List<SavedInstruction> saved = snapshot(p, at, end);
        var undo = Undo.of(p, at, end, override, saved);
        // A B B3 proven a call keeps its CALL override (issue #39).
        boolean isReturn = override == FlowOverride.RETURN || (override != FlowOverride.CALL &&
            original.getNumOperands()>0 && "B3".equals(original.getDefaultOperandRepresentation(0)) &&
                !original.getMnemonicString().startsWith("CALLP"));
        if(isReturn)override=FlowOverride.RETURN;
        listing.clearCodeUnits(at,end,false);
        try {
            p.getProgramContext().setValue(p.getRegister("c_flow_delay"),at,at,BigInteger.valueOf(bytes));
            if(registerBranch)
                p.getProgramContext().setValue(p.getRegister("c_branch_terminal"),at,at,BigInteger.ONE);
            // Never polled: a cancel here would leave the window half decoded.
            Disassembler disassembler=Disassembler.getDisassembler(p,TaskMonitor.DUMMY,null);
            disassembler.disassemble(at,new AddressSet(at,end),false);
            // The released slots after a terminal transfer are reached by no fall-through.
            if(end.compareTo(window.end())>0&&listing.getInstructionContaining(window.end().next())==null)
                disassembler.disassemble(window.end().next(),new AddressSet(window.end().next(),end),false);
            var branch=listing.getInstructionAt(at);var tail=listing.getInstructionContaining(window.end());
            if(branch==null||branch.getPrototype().getDelaySlotByteCount()!=bytes||tail==null||!tail.isInDelaySlot())
                throw new IllegalStateException("Could not materialize native delay window at "+at+" end="+window.end()+" bytes="+bytes+" branch="+branch+" depth="+(branch==null?-1:branch.getDelaySlotDepth())+" tail="+tail);
            branch.setFlowOverride(override);
            restore(p, at, saved, isReturn, oldResume);
            long added=0;
            if(window.owner()!=null) {
                var body=new AddressSet(window.owner().getBody());long before=body.getNumAddresses();
                body.add(at,window.end());window.owner().setBody(body);added=body.getNumAddresses()-before;
            }
            return new Repair(at.toString(),window.end().toString(),bytes,oldDepth,branch.getDelaySlotDepth(),added);
        }
        catch (Exception failure) {
            throw undo.putBack(failure);
        }
    }

    private record SavedUnit(Address at, InstructionPrototype prototype, RegisterValue context, int length) { }

    /** What clearing [at, end] removes: instructions and their context, stored context, annotations. */
    private record Undo(Program p, Address at, Address end, FlowOverride override, List<SavedInstruction> saved,
            List<SavedUnit> units, Map<Address, RegisterValue> context) {
        static Undo of(Program p, Address at, Address end, FlowOverride override, List<SavedInstruction> saved) {
            var base = p.getLanguage().getContextBaseRegister();
            List<SavedUnit> units = new ArrayList<>();
            for (var ins : p.getListing().getInstructions(new AddressSet(at, end), true))
                units.add(new SavedUnit(ins.getAddress(), ins.getPrototype(), ins.getRegisterValue(base),
                    ins.isLengthOverridden() ? ins.getLength() : 0));
            Map<Address, RegisterValue> context = new HashMap<>();
            for (Address cursor = at; cursor.compareTo(end) <= 0; cursor = cursor.next())
                context.put(cursor, p.getProgramContext().getNonDefaultValue(base, cursor));
            return new Undo(p, at, end, override, saved, units, context);
        }

        /** Put the window back as it was before it was cleared; return failure to rethrow. */
        Exception putBack(Exception failure) {
            try {
                var listing = p.getListing();
                var programContext = p.getProgramContext();
                var base = p.getLanguage().getContextBaseRegister();
                listing.clearCodeUnits(at, end, false);
                for (var entry : context.entrySet()) {
                    Address cursor = entry.getKey();
                    if (Objects.equals(programContext.getNonDefaultValue(base, cursor), entry.getValue())) continue;
                    if (entry.getValue() == null) programContext.remove(cursor, cursor, base);
                    else programContext.setRegisterValue(cursor, cursor, entry.getValue());
                }
                for (var unit : units) {
                    var decode = new ProcessorContextImpl(p.getLanguage());
                    if (unit.context() != null) decode.setRegisterValue(unit.context());
                    listing.createInstruction(unit.at(), unit.prototype(),
                        new DumbMemBufferImpl(p.getMemory(), unit.at()), decode, unit.length());
                }
                var branch = listing.getInstructionAt(at);
                if (branch != null) branch.setFlowOverride(override);
                restore(p, at, saved, false, null);
            }
            catch (Exception again) {
                failure.addSuppressed(again);
            }
            return failure;
        }
    }

    /** Annotations in [at, end]. Undisassembled tail bytes can already carry user comments and refs. */
    private static List<SavedInstruction> snapshot(Program p, Address at, Address end) {
        var listing = p.getListing();
        List<SavedInstruction> saved = new ArrayList<>();
        // Snapshot every address, including those without a defined instruction.
        for(Address cursor=at;cursor.compareTo(end)<=0;cursor=cursor.next()) {
            var ins=listing.getInstructionAt(cursor);List<SavedRef> refs=new ArrayList<>();
            for(var r:p.getReferenceManager().getReferencesFrom(cursor))
                refs.add(new SavedRef(r,r.isPrimary(),r.getSymbolID()));
            String[] comments=new String[5];for(int i=0;i<5;i++)comments[i]=listing.getComment(i,cursor);
            saved.add(new SavedInstruction(cursor,ins==null?FlowOverride.NONE:ins.getFlowOverride(),comments,refs,ins!=null&&ins.isFallThroughOverridden(),ins==null?null:ins.getFallThrough()));
        }
        return saved;
    }

    /**
     * Restore a snapshot around the re-decoded branch at at, whose own override the
     * caller sets. A return drops its flow references; dropFallThrough is the
     * branch fall-through that belonged to a released window.
     */
    private static void restore(Program p, Address at, List<SavedInstruction> saved, boolean isReturn,
            Address dropFallThrough) {
        var listing = p.getListing();
        for(var snapshot:saved) {
            var ins=listing.getInstructionAt(snapshot.at());
            boolean issue=snapshot.at().equals(at);
            if(ins!=null&&!issue)ins.setFlowOverride(snapshot.override());
            if(ins!=null&&snapshot.fallThroughOverridden()&&
                    !(issue&&snapshot.fallThrough()!=null&&snapshot.fallThrough().equals(dropFallThrough)))
                ins.setFallThrough(snapshot.fallThrough());
            for(int i=0;i<5;i++)if(snapshot.comments()[i]!=null)listing.setComment(snapshot.at(),i,snapshot.comments()[i]);
            for(var ref:snapshot.references()) {
                var r=ref.reference();
                if(issue&&isReturn&&r.getReferenceType().isFlow())continue;
                // A dropped fall-through's reference goes with it.
                if(issue&&dropFallThrough!=null&&r.getReferenceType().isFallthrough()&&r.getToAddress().equals(dropFallThrough))continue;
                var manager=p.getReferenceManager();
                var restored=r.isRegisterReference() ? manager.addRegisterReference(r.getFromAddress(),r.getOperandIndex(),p.getRegister(r.getToAddress()),r.getReferenceType(),r.getSource()) : manager.addReference(r);
                manager.setPrimary(restored,ref.primary());
                var symbol=p.getSymbolTable().getSymbol(ref.symbolId());
                if(symbol!=null)manager.setAssociation(symbol,restored);
            }
        }
    }

    private static final class Reader {
        private final Program program;private final Listing listing;private final PseudoDisassembler pseudo;
        /** A branch window() treats as an ordinary companion (pairJumps' complement). */
        Address ignore;
        private final Map<Address,C6000CallAnalyzer.Preemption> cuts;
        /** cuts: the transfer of each continued jump (neutralise); null looks the preemption up. */
        Reader(Program p,Map<Address,C6000CallAnalyzer.Preemption> cuts){program=p;listing=p.getListing();pseudo=new PseudoDisassembler(p);this.cuts=cuts;}
        Reader(Program p){this(p,null);}
        Instruction decode(Address at) {
            if (at == null) return null;
            var old=listing.getInstructionAt(at);if(old!=null)return old;
            if(listing.getInstructionContaining(at)!=null||listing.getDefinedDataContaining(at)!=null)return null;
            try{return pseudo.disassemble(at);}catch(Exception e){return null;}
        }
        Instruction next(Instruction i){var next=decode(i.getMaxAddress().next());
            while(next!=null&&C6000CallAnalyzer.baseName(next).equals("CPKT"))next=decode(next.getMaxAddress().next());return next;}
        Window window(Instruction issue,TaskMonitor monitor)throws CancelledException{return window(issue,monitor,(Address)null);}
        /** tolerate: a branch in the window that carryCallArms is about to make inert. */
        Window window(Instruction issue,TaskMonitor monitor,Address tolerate)throws CancelledException {
            C6000CallAnalyzer.Preemption preemption=null;
            if(preemptingTransfer(issue)){
                if(cuts!=null)preemption=cuts.get(issue.getAddress());
                else{preemption=new C6000CallAnalyzer.Walker(program).preempting(issue);
                    if(preemption!=null&&!(preemption.exact()&&continues(program,preemption.jump())))preemption=null;}
            }
            return window(issue,monitor,preemption,tolerate);
        }
        Window window(Instruction issue,TaskMonitor monitor,C6000CallAnalyzer.Preemption preemption)throws CancelledException{return window(issue,monitor,preemption,null);}
        /** The window of issue, cut where preemption's jump lands when it is non-null. */
        Window window(Instruction issue,TaskMonitor monitor,C6000CallAnalyzer.Preemption preemption,Address tolerate)throws CancelledException {
            int remaining=5;
            String name=C6000CallAnalyzer.baseName(issue);
            if(name.startsWith("CALLP"))remaining=0;
            // A BNOP's NOP cycles count in its own packet (C6000ExecutionPackets.cycles).
            // Issued in a preempted jump's window: that jump lands first and its target only idles.
            Address cut=null;
            if(preemption!=null){remaining=5-preemption.cycle();cut=preemption.windowEnd();}
            var owner=program.getFunctionManager().getFunctionContaining(issue.getAddress());
            Instruction current=issue;int count=0;
            try {
                boolean issuePacket=true;
                do {
                    int cycles=issuePacket?packetCycles(issue):1;
                    if(cycles<0)return null;
                    Instruction nopGenerator=issuePacket&&C6000ExecutionPackets.startsMulticycleNop(issue)?issue:null;
                    int packetInstructions=issuePacket?1:0;
                    if(issuePacket)for(var priorAt:C6000ExecutionPackets.issuePrefix(program,issue.getAddress())) {
                        if(++packetInstructions>8)return null;
                        var prior=decode(priorAt);if(prior==null)return null;
                        if(!priorAt.equals(ignore)&&(prior.getFlowType().isJump()||prior.getFlowType().isCall()||prior.getFlowType().isTerminal()))return null;
                        var priorOwner=program.getFunctionManager().getFunctionContaining(priorAt);
                        // A physical predecessor's p bit does not prove that
                        // an alternate entry executed it. The prefix must share
                        // the issue's ownership, and incoming control into this
                        // suffix is rejected below. A call a flow repair just
                        // disassembled (e.g. a switch-merge target) is not yet
                        // in any function body when recovery runs over it;
                        // accept owner==null when the prefix is unowned too, not
                        // only when both are the same function.
                        if(owner==null?priorOwner!=null:!owner.equals(priorOwner))return null;
                        var incoming=program.getReferenceManager().getReferencesTo(issue.getAddress());
                        while(incoming.hasNext())if(incoming.next().getReferenceType().isFlow())return null;
                        if(C6000ExecutionPackets.startsMulticycleNop(prior)) {
                            if(nopGenerator!=null&&!C6000ExecutionPackets.sameMulticycleNop(nopGenerator,prior))return null;
                            nopGenerator=prior;
                        }
                        int priorCycles=packetCycles(prior);if(priorCycles<0)return null;
                        cycles=Math.max(cycles,priorCycles);
                    }
                    while(!issuePacket||C6000ExecutionPackets.parallelWithNext(program,current)) {
                        monitor.checkCancelled();if(++packetInstructions>8)return null;var next=next(current);if(next==null||++count>MAX_INSTRUCTIONS)return null;
                        if(next.getAddress().subtract(issue.getMaxAddress())>MAX_BYTES)return null;
                        if(!next.getAddress().equals(ignore)&&!next.getAddress().equals(tolerate)&&(next.getFlowType().isJump()||next.getFlowType().isCall()||next.getFlowType().isTerminal()))return null;
                        // A call's window over an inert branch hides the slots past it from flow (Ghidra counts slots by parsing them): refuse it, as before the branch was carried.
                        if(flag(program,next.getAddress(),"c_inert")&&(issue.getFlowType().isCall()||issue.getFlowOverride()==FlowOverride.CALL))return null;
                        var other=program.getFunctionManager().getFunctionContaining(next.getAddress());
                        if(other!=null&&!other.equals(owner))return null;
                        if(program.getFunctionManager().getFunctionAt(next.getAddress())!=null)return null;
                        if(C6000ExecutionPackets.startsMulticycleNop(next)) {
                            if(nopGenerator!=null&&!C6000ExecutionPackets.sameMulticycleNop(nopGenerator,next))return null;
                            nopGenerator=next;
                        }
                        int nextCycles=packetCycles(next);if(nextCycles<0)return null;
                        cycles=Math.max(cycles,nextCycles);current=next;
                        if(!C6000ExecutionPackets.parallelWithNext(program,current))break;
                    }
                    if(!issuePacket)remaining-=cycles;else remaining-=cycles-1;
                    issuePacket=false;
                }while(remaining>0);
                if(cut!=null&&!cut.equals(current.getMaxAddress()))return null;
                return new Window(issue,current.getMaxAddress(),owner);
            }catch(MemoryAccessException e){return null;}
        }
        int packetCycles(Instruction i)throws MemoryAccessException {
            Integer cycles=C6000ExecutionPackets.cycles(program,i);
            return cycles==null?-1:cycles;}
        /** pairJumps: the one other branch in y's packet, on y's complementary predicate, when y is a displacement B. */
        Instruction complement(Instruction y) {
            String name = C6000CallAnalyzer.baseName(y);
            if (!(name.equals("B.S1") || name.equals("B.S2")) || y.getLength() != 4 || y.getRegister(0) != null ||
                    y.isInDelaySlot() || y.getFlowOverride() != FlowOverride.NONE || y.getDefaultFlows().length != 1) return null;
            if (flag(program, y.getAddress(), "c_inert") || flag(program, y.getAddress(), "c_carry") || continues(program, y)) return null;
            try {
                var own = packet(y.getAddress());
                if (own == null) return null;
                Instruction x = null;
                for (Instruction i : own) {
                    if (i.getAddress().equals(y.getAddress()) || !transfer(i)) continue;
                    if (x != null || !complementary(i, y)) return null;
                    x = i;
                }
                if (x == null || x.isInDelaySlot() || flag(program, x.getAddress(), "c_carry")) return null;
                String xn = C6000CallAnalyzer.baseName(x);
                var o = x.getFlowOverride();
                if (!(xn.equals("B.S1") || xn.equals("B.S2")) || x.getLength() != 4 || x.getFlowType().isCall() ||
                        !(o == FlowOverride.NONE || o == FlowOverride.RETURN)) return null;
                return x;
            }
            catch (MemoryAccessException e) {
                return null;
            }
        }

        /** inertJumps: an unconditional-or-not displacement B landing where sequential issue is, with nothing else pending. */
        boolean inSequence(Instruction x, TaskMonitor monitor) throws CancelledException {
            String name = C6000CallAnalyzer.baseName(x);
            var override = x.getFlowOverride();
            // A jump to a seeded entry may be taken as a tail call; landing in sequence, it is neither.
            if (!(name.equals("B.S1") || name.equals("B.S2")) || x.getLength() != 4 || x.getRegister(0) != null || x.isInDelaySlot() ||
                    !(override == FlowOverride.NONE || override == FlowOverride.BRANCH || override == FlowOverride.CALL_RETURN)) return false;
            Address at = x.getAddress();
            if (flag(program, at, "c_inert") || flag(program, at, "c_carry") || continues(program, x)) return false;
            if (x.getDefaultFlows().length != 1) return false;
            Address target = x.getDefaultFlows()[0];
            try {
                List<Instruction> own = packet(at);
                if (own == null) return false;
                for (Instruction y : own) if (y != null && !y.getAddress().equals(at) && transfer(y) && !complementary(y, x)) return false;
                // Forward: the packet issuing in the landing cycle is the target.
                int remaining = 5 - (cycles(own) - 1);
                List<List<Instruction>> walked = new ArrayList<>();
                Instruction last = own.get(own.size() - 1);
                while (remaining > 0) {
                    monitor.checkCancelled();
                    Instruction first = next(last);
                    if (first == null || walked.size() > 8) return false;
                    var p = packet(first.getAddress());
                    if (p == null || !p.get(0).getAddress().equals(first.getAddress())) return false;
                    int c = cycles(p);
                    if (c < 0) return false;
                    remaining -= c; last = p.get(p.size() - 1); walked.add(p);
                }
                if (remaining < 0 || !resume(program, last.getMaxAddress()).equals(target)) return false;
                for (var p : walked) if (!onlyJumpedTo(p.get(0).getAddress(), null)) return false;
                // A window entered from outside keeps its native treatment (issue #52 relief): only x's own run reaches it.
                for (var p : walked) for (Instruction m : p)
                    for (var it = program.getReferenceManager().getReferencesTo(m.getAddress()); it.hasNext();) {
                        Reference r = it.next();
                        Address from = r.getFromAddress();
                        if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough() &&
                                (from.compareTo(at) < 0 || from.compareTo(target) >= 0)) return false;
                    }
                if (!onlyJumpedTo(target, at)) return false;
                // Backward: no branch issued in the five cycles before is still pending, nor one a jump in brought along.
                // A complementary one is never taken with x while its predicate register holds (writes up to 4 cycles earlier may land).
                List<List<Instruction>> before = new ArrayList<>();
                List<Integer> distance = new ArrayList<>();
                List<Instruction> pending = new ArrayList<>();
                List<Integer> pendingAt = new ArrayList<>();
                before.add(own); distance.add(0);
                Address start = own.get(0).getAddress();
                for (int back = 0; back <= 15 && program.getFunctionManager().getFunctionAt(start) == null;) {
                    monitor.checkCancelled();
                    Address prior = packetBefore(start);
                    if (prior == null) { if (back <= 5) return false; break; }
                    var p = packet(prior);
                    if (p == null || cycles(p) < 0) { if (back <= 5) return false; break; }
                    back += cycles(p);
                    if (back <= 5) for (Instruction y : p) if (transfer(y)) {
                        if (!complementary(y, x)) return false;
                        pending.add(y); pendingAt.add(back);
                    }
                    before.add(p); distance.add(back); start = p.get(0).getAddress();
                }
                // A write issued d cycles before x lands (latency) cycles later; one landing after y read the predicate and by x's issue changes it.
                for (int k = 0; k < pending.size(); k++) {
                    var reg = predicate(pending.get(k));
                    for (int q = 1; q < before.size(); q++) {
                        for (Instruction w : before.get(q)) {
                            int v = distance.get(q) - latency(w);
                            if (v < 0 || v >= pendingAt.get(k)) continue;
                            for (Object o : C6000PacketContext.architecturalResults(program, w))
                                if (o instanceof ghidra.program.model.lang.Register r && (reg == null || r.contains(reg) || reg.contains(r))) return false;
                        }
                    }
                }
                while (before.size() > 1 && distance.get(before.size() - 1) > 5) { before.remove(before.size() - 1); distance.remove(distance.size() - 1); }
                var references = program.getReferenceManager();
                for (var p : before) for (Instruction m : p) {
                    // A function is entered drained, as the lookback above assumes: its callers are its own concern.
                    if (program.getFunctionManager().getFunctionAt(m.getAddress()) != null) continue;
                    for (var it = references.getReferencesTo(m.getAddress()); it.hasNext();) {
                        Reference r = it.next();
                        if (!r.getReferenceType().isFlow() || r.getReferenceType().isFallthrough()) continue;
                        Instruction j = listing.getInstructionAt(r.getFromAddress());
                        if (j == null || !quiet(j, monitor)) return false;
                    }
                }
                return true;
            }
            catch (MemoryAccessException e) {
                return false;
            }
        }

        /** No function starts at at, or only jumps (and any flow from from) reach it: nothing else calls it or points to it. */
        private boolean onlyJumpedTo(Address at, Address from) {
            if (program.getFunctionManager().getFunctionAt(at) == null) return true;
            for (var it = program.getReferenceManager().getReferencesTo(at); it.hasNext();) {
                Reference r = it.next();
                if (!r.getReferenceType().isJump() && !(r.getFromAddress().equals(from) && r.getReferenceType().isFlow())) return false;
            }
            return !program.getSymbolTable().isExternalEntryPoint(at);
        }

        /** No branch but j itself, or one never taken with it, issues in j's packet or the five cycles after it. */
        private boolean quiet(Instruction j, TaskMonitor monitor) throws CancelledException, MemoryAccessException {
            var own = packet(j.getAddress());
            if (own == null) return false;
            for (Instruction y : own) if (!y.getAddress().equals(j.getAddress()) && transfer(y) && !complementary(y, j)) return false;
            // A branch complementary to j is not taken with it while their predicate register holds.
            List<Instruction> between = new ArrayList<>(own);
            Address start = own.get(0).getAddress();
            for (int back = 0; back < 5 && program.getFunctionManager().getFunctionAt(start) == null;) {
                Address prior = packetBefore(start);
                var p = prior == null ? null : packet(prior);
                if (p == null || cycles(p) < 0) return false;
                back += cycles(p); start = p.get(0).getAddress();
                for (Instruction w : p) if (latency(w) > back) between.add(w);
            }
            int remaining = 5 - (cycles(own) - 1);
            Instruction last = own.get(own.size() - 1);
            for (int n = 0; remaining > 0; n++) {
                monitor.checkCancelled();
                Instruction first = next(last);
                if (first == null || n > 8) return false;
                var p = packet(first.getAddress());
                if (p == null) return false;
                int c = cycles(p);
                if (c < 0) return false;
                for (Instruction y : p) if (transfer(y) && (!complementary(y, j) || writes(between, predicate(y)))) return false;
                between.addAll(p);
                remaining -= c; last = p.get(p.size() - 1);
            }
            return true;
        }

        /** Whether any of the instructions writes reg (or reg is unknown). */
        private boolean writes(List<Instruction> list, ghidra.program.model.lang.Register reg) {
            if (reg == null) return true;
            for (Instruction w : list) for (Object o : C6000PacketContext.architecturalResults(program, w))
                if (o instanceof ghidra.program.model.lang.Register r && (r.contains(reg) || reg.contains(r))) return true;
            return false;
        }

        /** The whole execute packet holding at, decoded; null for compact or undecodable code. */
        private List<Instruction> packet(Address at) throws MemoryAccessException {
            List<Address> prefix = C6000ExecutionPackets.issuePrefix(program, at);
            Address start = prefix.isEmpty() ? at : prefix.get(0);
            List<Instruction> members = new ArrayList<>();
            for (Address a : C6000ExecutionPackets.packetMembers(program, start)) {
                Instruction i = decode(a);
                if (i == null || i.getLength() != 4 || flag(program, a, "c_hdrpkt")) return null;
                members.add(i);
            }
            return members.contains(null) || members.stream().noneMatch(i -> i.getAddress().equals(at)) ? null : members;
        }

        /** Start of the execute packet before the one starting at start, in full-width code. */
        private Address packetBefore(Address start) throws MemoryAccessException {
            if (start.getOffset() < 4) return null;
            Address prior = start.subtract(4);
            if (!program.getMemory().contains(prior) || (program.getMemory().getInt(prior) >>> 28) == 0xe &&
                    (prior.getOffset() & 31) == 28) return null;
            List<Address> prefix = C6000ExecutionPackets.issuePrefix(program, prior);
            return prefix.isEmpty() ? prior : prefix.get(0);
        }

        /** Cycles the packet occupies; -1 for a member whose timing this walk does not model. */
        private int cycles(List<Instruction> packet) throws MemoryAccessException {
            int c = 1;
            for (Instruction i : packet) {
                String name = C6000CallAnalyzer.baseName(i);
                if (name.startsWith("BNOP") || name.startsWith("CALLP") || name.startsWith("SPMASK")) return -1;
                int n = packetCycles(i);
                if (n < 0) return -1;
                c = Math.max(c, n);
            }
            return c;
        }

        /** Any branch still to land, except one made inert. */
        private boolean transfer(Instruction i) {
            if (flag(program, i.getAddress(), "c_inert")) return false;
            if (flag(program, i.getAddress(), "c_carry")) return true;
            String name = C6000CallAnalyzer.baseName(i);
            var flow = i.getFlowType();
            return name.startsWith("B.") || name.startsWith("BNOP") || name.startsWith("CALLP") || name.startsWith("BDEC") ||
                name.startsWith("BPOS") || flow.isJump() || flow.isCall() || flow.isTerminal();
        }

        /** Cycles until a write is visible: 1, 5 for a load, and a conservative 10 for multiplies and floating point (SPRUFE8B Table 3-8). */
        private static int latency(Instruction w) {
            String n = C6000CallAnalyzer.baseName(w);
            if (n.startsWith("LD")) return 5;
            String op = n.contains(".") ? n.substring(0, n.indexOf('.')) : n;
            if (op.startsWith("MPY") || op.startsWith("INT") || op.contains("SP") || op.contains("DP") || op.startsWith("SMPY")) return 10;
            return 1;
        }

        /** The predicate register of a full-width instruction (SPRUFE8B Table 3-9), or null. */
        private ghidra.program.model.lang.Register predicate(Instruction i) {
            try {
                String[] names = { null, "B0", "B1", "B2", "A1", "A2", "A0", null };
                String n = names[program.getMemory().getInt(i.getAddress()) >>> 29];
                return n == null ? null : program.getRegister(n);
            }
            catch (MemoryAccessException e) {
                return null;
            }
        }

        /** Same predicate register, opposite sense: never both taken. */
        private boolean complementary(Instruction y, Instruction x) {
            try {
                int a = program.getMemory().getInt(y.getAddress()), b = program.getMemory().getInt(x.getAddress());
                int ca = a >>> 29, cb = b >>> 29;
                return ca != 0 && ca != 7 && ca == cb && ((a >>> 28) & 1) != ((b >>> 28) & 1);
            }
            catch (MemoryAccessException e) {
                return false;
            }
        }

    }
}
