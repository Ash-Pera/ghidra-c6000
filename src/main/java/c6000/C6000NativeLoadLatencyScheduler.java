// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.util.PseudoInstruction;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

/** Defers a load result read in its delay slots to the packet issued 5 cycles later, or refuses (SPRUFE8B 3.4, 4.2.5, Table 4-10; docs/internals.md). */
final class C6000NativeLoadLatencyScheduler {
    /** The packet issued this many cycles after a load is the first to read its result. */
    static final int LOAD_LATENCY = 5;
    private static final int BRANCH_DELAY = 5;  // B/BNOP/CALLP delay slots (SPRUFE8B 4.2.6)
    private static final int LONGEST_WRITE = 10;  // MPYDP writes in E10 (docs/pipeline-schedules.md)
    private static final int PAIR_SELECTOR = 64;
    private static final Set<String> LATE_READS = Set.of("ADDDP", "SUBDP", "MPYDP", "MPYSPDP",
        "CMPEQDP", "CMPLTDP", "CMPGTDP", "MPYI", "MPYID");
    private static final Set<String> CONTROL = Set.of("B", "BNOP", "CALLP", "BDEC", "BPOS",
        "IDLE", "SPLOOP", "SPLOOPD", "SPLOOPW", "SPKERNEL", "SPKERNELR", "SPMASK", "SPMASKR");
    private static final List<String> FLOW_FIELDS = List.of("c_flow_delay", "c_schedule_entry",
        "c_branch_terminal", "c_inert", "c_carry", "c_arm", "c_pair");

    record Finding(Address at, String reason) {}

    /** One load read before it lands; accepted when refusal is null. */
    record Decision(Address load, Address landing, int selector, Set<String> destination,
            Address reader, String refusal) {}

    private record Member(Instruction listed, Set<String> reads, Set<String> writes,
            String op, String predicate, boolean control, PcodeOp[] raw) {}
    private record Packet(Address start, List<Member> members, int cycle, int span) {}
    private record SavedInstruction(Address address, int length, FlowOverride override,
            boolean fallThroughOverridden, Address fallThrough) {}
    private record SavedReference(Reference reference, boolean primary, long symbolId) {}
    private record SavedComment(Address address, int type, String comment) {}

    private C6000NativeLoadLatencyScheduler() {}

    /** Applies accepted deferrals, clears every other mark in the body, and returns the decisions. */
    static List<Decision> schedule(Program program, Function function, TaskMonitor monitor)
            throws Exception {
        List<Decision> decisions = plan(program, function, monitor);
        Map<Address, int[]> wanted = marks(decisions);
        apply(program, function, wanted, monitor);
        List<Decision> result = new ArrayList<>();
        boolean revoke = false;
        for (Decision decision : decisions) {
            if (decision.refusal() == null && !inEffect(program, decision)) {
                decision = refused(decision, "the deferral wrapper did not decode at the load or its landing packet");
                revoke = true;
            }
            result.add(decision);
        }
        if (revoke) apply(program, function, marks(result), monitor);
        return List.copyOf(result);
    }

    /** The first load still lifted inexactly, or null. */
    static Finding finding(Program program, Function function, TaskMonitor monitor)
            throws Exception {
        for (Decision decision : plan(program, function, monitor)) {
            if (decision.refusal() == null && inEffect(program, decision)) continue;
            String reason = "reads " + String.join("/", decision.destination()) +
                " before the load at " + decision.load() + " lands; native lifting exposes the " +
                "loaded value early (enable an exact schedule)";
            return new Finding(decision.reader(), decision.refusal() == null ? reason
                : reason + "; native deferral refused: " + decision.refusal());
        }
        return null;
    }

    /** Functions holding a deferral mark, so a late reference can revoke it. */
    static Set<Function> marked(Program program) {
        Set<Function> result = new LinkedHashSet<>();
        Register mode = program.getRegister("c_load_mode");
        if (mode == null) return result;
        var ranges = program.getProgramContext().getRegisterValueAddressRanges(mode);
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            for (Address at : List.of(range.getMinAddress(), range.getMaxAddress())) {
                Function owner = program.getFunctionManager().getFunctionContaining(at);
                if (owner != null) result.add(owner);
            }
        }
        return result;
    }

    static List<Decision> plan(Program program, Function function, TaskMonitor monitor)
            throws Exception {
        if (contextValue(program, "c_schedule_entry", function.getEntryPoint()) != 0) return List.of();
        List<Packet> timeline = timeline(program, function);
        boolean loopBuffer = timeline.stream().flatMap(p -> p.members().stream())
            .anyMatch(m -> m.op().startsWith("SPLOOP"));
        List<Decision> decisions = new ArrayList<>();
        List<int[]> spans = new ArrayList<>();
        for (int i = 0; i < timeline.size(); i++) {
            monitor.checkCancelled();
            for (Member load : timeline.get(i).members()) {
                if (!load.op().startsWith("LD")) continue;
                Decision decision = decide(program, function, timeline, i, load, loopBuffer);
                if (decision == null) continue;
                decisions.add(decision);
                int landing = timeline.get(i).cycle() + LOAD_LATENCY;
                for (Packet packet : timeline) {
                    if (packet.start().equals(decision.landing())) landing = packet.cycle();
                }
                spans.add(new int[] { timeline.get(i).cycle(), landing });
            }
        }
        // One shadow: two accepted results in flight in the same cycles are both refused.
        List<Decision> result = new ArrayList<>();
        for (int i = 0; i < decisions.size(); i++) {
            Decision decision = decisions.get(i);
            boolean crowded = false;
            for (int j = 0; j < decisions.size(); j++) {
                crowded |= j != i && decision.refusal() == null && decisions.get(j).refusal() == null &&
                    spans.get(i)[0] <= spans.get(j)[1] && spans.get(j)[0] <= spans.get(i)[1];
            }
            result.add(crowded ? refused(decision, "another deferred load result is in flight in the same cycles") : decision);
        }
        return List.copyOf(result);
    }

    private static Map<Address, int[]> marks(List<Decision> decisions) {
        Map<Address, int[]> wanted = new LinkedHashMap<>();
        for (Decision decision : decisions) {
            if (decision.refusal() != null) continue;
            wanted.put(decision.load(), new int[] { 1, decision.selector() });
            wanted.put(decision.landing(), new int[] { 2, decision.selector() });
        }
        return wanted;
    }

    private static Decision decide(Program program, Function function, List<Packet> timeline,
            int issue, Member load, boolean loopBuffer) throws Exception {
        Set<String> destination;
        boolean known = true;
        try {
            destination = loadWrites(program, load.raw());
        }
        catch (IllegalArgumentException unknownFlow) {
            destination = load.writes();
            known = false;
        }
        if (destination.isEmpty()) return null;
        int cycle = timeline.get(issue).cycle();
        Address reader = reader(timeline, issue, load, destination);
        if (reader == null) return null;
        int landing = issue + 1;
        while (landing < timeline.size() && timeline.get(landing).cycle() < cycle + LOAD_LATENCY) landing++;
        Address landingAt = landing < timeline.size() ? timeline.get(landing).start() : null;
        int selector = known ? selector(destination) : 0;
        Decision decision = new Decision(load.listed().getAddress(), landingAt, selector,
            Set.copyOf(destination), reader, null);
        String refusal = refusal(program, function, timeline, issue, landing, load, destination,
            selector, loopBuffer);
        return refusal == null ? decision : refused(decision, refusal);
    }

    /** The warning's trigger: a read of the destination before E5, not ended by an unconditional rewrite. */
    private static Address reader(List<Packet> timeline, int issue, Member load,
            Set<String> destination) {
        Set<String> tracked = new LinkedHashSet<>(destination);
        int land = timeline.get(issue).cycle() + LOAD_LATENCY;
        for (int j = issue; j < timeline.size() && timeline.get(j).cycle() < land; j++) {
            for (Member later : timeline.get(j).members()) {
                if (later == load) continue;
                if (later.reads().stream().anyMatch(tracked::contains)) return later.listed().getAddress();
            }
            for (Member later : timeline.get(j).members()) {
                if (later != load && !later.op().startsWith("LD") && later.predicate() == null) {
                    tracked.removeAll(later.writes());
                }
            }
            if (tracked.isEmpty()) return null;
        }
        return null;
    }

    private static String refusal(Program program, Function function, List<Packet> timeline,
            int issue, int landing, Member load, Set<String> destination, int selector,
            boolean loopBuffer) throws Exception {
        int cycle = timeline.get(issue).cycle();
        Address loadAt = load.listed().getAddress();
        if (selector == 0) return "the load destination is not one register or an aligned pair";
        if (loopBuffer) return "the function uses the SPLOOP buffer, whose issue order is not address order";
        if (leavesInstruction(load.raw())) return "the load's p-code leaves the instruction, so its shadow could be skipped";
        for (PcodeOp op : load.raw()) {
            if (op.getOpcode() == PcodeOp.UNIMPLEMENTED) return "the load has opaque native semantics";
        }
        if (nonLoadWrites(program, load.raw()).stream().anyMatch(destination::contains)) {
            return "the load updates its destination register in E1";
        }
        if (landing >= timeline.size()) return "the load lands outside the decoded straight-line body";
        for (int j = issue; j < landing; j++) {
            if (timeline.get(j).span() < 0) return "a multicycle NOP generator in the load window has no fixed count";
        }
        // A transfer issued here, or one whose delay slots hold the load, leaves address order.
        for (int j = issue; j >= 0 && timeline.get(j).cycle() >= cycle - BRANCH_DELAY; j--) {
            for (Member member : timeline.get(j).members()) {
                if (j < issue && (member.control() || member.listed().isInDelaySlot())) {
                    return "a branch or call issues within five cycles before the load";
                }
            }
        }
        for (int j = issue; j < landing; j++) {
            for (Member member : timeline.get(j).members()) {
                if (member.control() || member.listed().isInDelaySlot()) {
                    return "a branch or call issues inside the load window";
                }
            }
        }
        Set<String> inputs = new LinkedHashSet<>(load.reads());
        boolean staged = parallelStaged(program, loadAt);
        boolean earlier = true;
        for (Member member : timeline.get(issue).members()) {
            if (member == load) {
                earlier = false;
                continue;
            }
            if (member.reads().stream().anyMatch(destination::contains)) {
                return "a parallel member reads the load destination";
            }
            if (member.writes().stream().anyMatch(destination::contains)) {
                return "another instruction writes the load destination in its window";
            }
            for (String written : earlier && !staged ? member.writes() : Set.<String>of()) {
                if (!inputs.contains(written)) continue;
                return written.equals(load.predicate())
                    ? "an earlier member of its unstaged packet writes the load predicate " + written
                    : "an earlier member of its unstaged packet writes load input " + written;
            }
        }
        for (int j = issue + 1; j <= landing; j++) {
            for (Member member : timeline.get(j).members()) {
                if (member.writes().stream().anyMatch(destination::contains)) {
                    return j == landing ? "another instruction writes the load destination in its landing packet"
                        : "another instruction writes the load destination in its window";
                }
                if (j < landing && LATE_READS.contains(member.op()) &&
                        member.reads().stream().anyMatch(destination::contains)) {
                    return "a multi-cycle source read of the destination reaches the landing cycle";
                }
            }
        }
        // Native lifting writes at issue, so an earlier write still pending at the load's E1 is reordered.
        for (int j = issue - 1; j >= 0 && timeline.get(j).cycle() > cycle - LONGEST_WRITE; j--) {
            for (Member member : timeline.get(j).members()) {
                if (member.writes().stream().noneMatch(destination::contains)) continue;
                int phase = member.op().startsWith("LD") ? LOAD_LATENCY
                    : C6000PipelineCompiler.SINGLE.contains(member.op()) ? 1 : LONGEST_WRITE;
                if (timeline.get(j).cycle() + phase - 1 >= cycle) {
                    return "an earlier write of the destination is still in flight at the load";
                }
            }
        }
        Address landingAt = timeline.get(landing).start();
        if (entered(program, loadAt, landingAt)) {
            return "a flow target or function entry lies between the load and its landing packet";
        }
        for (Address at : List.of(loadAt, landingAt)) {
            if (contextValue(program, "c_carry", at) != 0 || contextValue(program, "c_schedule_entry", at) != 0) {
                return "the load or its landing packet carries another native wrapper";
            }
        }
        return null;
    }

    /** Any reference, entry point or function start after the load through the landing packet start. */
    private static boolean entered(Program program, Address load, Address landing) {
        ReferenceManager references = program.getReferenceManager();
        var symbols = program.getSymbolTable();
        for (Address at = load.next(); at != null && at.compareTo(landing) <= 0; at = at.next()) {
            if (references.hasReferencesTo(at) || symbols.isExternalEntryPoint(at) ||
                    program.getFunctionManager().getFunctionAt(at) != null) return true;
        }
        return false;
    }

    private static Decision refused(Decision decision, String reason) {
        return new Decision(decision.load(), decision.landing(), decision.selector(),
            decision.destination(), decision.reader(), reason);
    }

    /** Straight-line execute packets of the body in address order, each with its issue cycle. */
    private static List<Packet> timeline(Program program, Function function) throws Exception {
        Listing listing = program.getListing();
        List<Packet> packets = new ArrayList<>();
        int cycle = 0;
        Address at = function.getEntryPoint();
        Set<Address> seen = new HashSet<>();
        while (at != null && function.getBody().contains(at) && seen.add(at)) {
            List<Address> addresses;
            int span;
            try {
                addresses = C6000ExecutionPackets.packetMembers(program, at);
                try {
                    span = C6000ExecutionPackets.issueCycles(program, addresses);
                }
                catch (MemoryAccessException conflicting) {
                    span = -1;
                }
            }
            catch (MemoryAccessException incomplete) {
                break;
            }
            List<Member> members = new ArrayList<>();
            for (Address address : addresses) {
                Instruction listed = listing.getInstructionAt(address);
                if (listed == null || !function.getBody().contains(address)) break;
                members.add(member(program, listed));
            }
            if (members.size() != addresses.size()) break;
            for (Member member : members) {
                // PROT inserts four NOP cycles after a load (SPRUFE8B 3.10.2.2).
                if (C6000ExecutionPackets.protectedLoad(program, member.listed())) span = span == 1 ? LOAD_LATENCY : -1;
            }
            packets.add(new Packet(at, List.copyOf(members), cycle, span));
            cycle += Math.max(1, span);
            try {
                at = C6000ExecutionPackets.nextIssue(program, addresses.get(addresses.size() - 1));
            }
            catch (MemoryAccessException end) {
                break;
            }
        }
        return List.copyOf(packets);
    }

    private static Member member(Program program, Instruction listed) throws Exception {
        Instruction raw = raw(program, listed.getAddress());
        PcodeOp[] code = raw.getPcode(false);
        Set<String> reads = new LinkedHashSet<>();
        Set<String> writes = new LinkedHashSet<>();
        for (PcodeOp op : code) {
            for (Varnode input : op.getInputs()) reads.addAll(gprs(program, input));
            writes.addAll(gprs(program, op.getOutput()));
        }
        String op = op(raw);
        var flow = raw.getFlowType();
        boolean control = CONTROL.contains(op) || flow.isJump() || flow.isCall() || flow.isTerminal();
        return new Member(listed, Set.copyOf(reads), Set.copyOf(writes), op, predicate(raw),
            control, code);
    }

    /** Physical decode without native staging or flow context: the instruction's own semantics. */
    private static Instruction raw(Program program, Address at) throws Exception {
        var context = new ProcessorContextImpl(program.getLanguage());
        for (var field : C6000PacketContext.physicalDecodeFields(program, at).entrySet()) {
            setContext(context, program, field.getKey(), field.getValue());
        }
        for (String name : C6000PacketContext.STAGING_FIELDS) setContext(context, program, name, 0);
        for (String name : FLOW_FIELDS) setContext(context, program, name, 0);
        var memory = new DumbMemBufferImpl(program.getMemory(), at);
        var prototype = program.getLanguage().parse(memory, context, false);
        return new PseudoInstruction(program, at, prototype, memory, context);
    }

    private static void setContext(ProcessorContextImpl context, Program program, String name,
            int value) {
        Register register = program.getRegister(name);
        if (register != null) context.setRegisterValue(new RegisterValue(register, BigInteger.valueOf(value)));
    }

    private static Set<String> loadWrites(Program program, PcodeOp[] code) {
        Set<String> result = new LinkedHashSet<>();
        for (int index : C6000MemoryWritePhases.loadWrites(code)) result.addAll(gprs(program, code[index].getOutput()));
        return result;
    }

    private static Set<String> nonLoadWrites(Program program, PcodeOp[] code) {
        Set<Integer> loaded = C6000MemoryWritePhases.loadWrites(code);
        Set<String> result = new LinkedHashSet<>();
        for (int i = 0; i < code.length; i++) {
            if (!loaded.contains(i)) result.addAll(gprs(program, code[i].getOutput()));
        }
        return result;
    }

    /** A predicate skip must stay inside the instruction, or the shadow copy after it is lost. */
    private static boolean leavesInstruction(PcodeOp[] code) {
        for (PcodeOp op : code) {
            switch (op.getOpcode()) {
                case PcodeOp.BRANCH, PcodeOp.CBRANCH -> {
                    if (!op.getInput(0).isConstant()) return true;
                }
                case PcodeOp.BRANCHIND, PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.RETURN -> {
                    return true;
                }
                default -> { }
            }
        }
        return false;
    }

    private static Set<String> gprs(Program program, Varnode node) {
        if (node == null || !node.isRegister() || !node.getAddress().getAddressSpace()
                .equals(program.getAddressFactory().getRegisterSpace())) return Set.of();
        long start = node.getOffset();
        long end = start + node.getSize();
        Set<String> result = new LinkedHashSet<>();
        for (String bank : List.of("A", "B")) {
            for (int i = 0; i < 32; i++) {
                Register register = program.getRegister(bank + i);
                long first = register.getAddress().getOffset();
                if (start < first + register.getMinimumByteSize() && first < end) result.add(bank + i);
            }
        }
        return result;
    }

    /** 1-64 for one GPR, 65-96 for an aligned pair (tools/gen_packet_sinc.py). */
    static int selector(Set<String> registers) {
        List<String> ordered = registers.stream()
            .sorted(Comparator.comparingInt(C6000NativeLoadLatencyScheduler::registerIndex)).toList();
        if (ordered.size() == 1) return registerIndex(ordered.get(0)) + 1;
        if (ordered.size() != 2) return 0;
        int low = registerIndex(ordered.get(0));
        if ((low & 1) != 0 || registerIndex(ordered.get(1)) != low + 1) return 0;
        return PAIR_SELECTOR + low / 2 + 1;
    }

    private static int registerIndex(String name) {
        return (name.charAt(0) == 'A' ? 0 : 32) + Integer.parseInt(name.substring(1));
    }

    private static String op(Instruction instruction) {
        String name = C6000CallAnalyzer.baseName(instruction).trim();
        int unit = name.indexOf('.');
        return unit >= 0 ? name.substring(0, unit) : name;
    }

    /** "[!B0] LDW.D1T1" -> "B0"; null when unconditional. */
    private static String predicate(Instruction instruction) {
        String mnemonic = instruction.getMnemonicString();
        int close = mnemonic.indexOf(']');
        if (!mnemonic.startsWith("[") || close < 0) return null;
        String name = mnemonic.substring(1, close);
        return name.startsWith("!") ? name.substring(1) : name;
    }

    /** The listing p-code really shadows at the load and commits at the landing packet. */
    private static boolean inEffect(Program program, Decision decision) {
        if (decision.landing() == null) return false;
        Listing listing = program.getListing();
        Instruction load = listing.getInstructionAt(decision.load());
        Instruction landing = listing.getInstructionAt(decision.landing());
        if (load == null || landing == null) return false;
        Address shadow = program.getRegister("C6000_LOAD_VALUE0").getAddress();
        boolean shadowed = false;
        for (PcodeOp op : load.getPcode(false)) {
            shadowed |= op.getOutput() != null && op.getOutput().getAddress().equals(shadow);
        }
        boolean committed = false;
        for (PcodeOp op : landing.getPcode(false)) {
            for (Varnode input : op.getInputs()) committed |= input.getAddress().equals(shadow);
        }
        return shadowed && committed &&
            contextValue(program, "c_load_reg", decision.load()) == decision.selector() &&
            contextValue(program, "c_load_reg", decision.landing()) == decision.selector();
    }

    /** The deferral shares the staging wrapper: c_pkt_active stays 1 only for a mark or a staged packet. */
    private static int active(Program program, Address at, int mode) {
        return mode != 0 || parallelStaged(program, at) ? 1 : 0;
    }

    /** C6000ParallelReadScheduler staged this instruction's packet (its first member has c_pkt_start). */
    private static boolean parallelStaged(Program program, Address at) {
        try {
            List<Address> prefix = C6000ExecutionPackets.issuePrefix(program, at);
            return contextValue(program, "c_pkt_start", prefix.isEmpty() ? at : prefix.get(0)) != 0;
        }
        catch (MemoryAccessException unknown) {
            return contextValue(program, "c_pkt_active", at) != 0;
        }
    }

    private static int contextValue(Program program, String name, Address at) {
        Register register = program.getRegister(name);
        if (register == null) return 0;
        BigInteger value = program.getProgramContext().getValue(register, at, false);
        return value == null ? 0 : value.intValue();
    }

    /** Sets the wanted marks, clears every other mark in this function's body, and re-decodes what changed. */
    private static void apply(Program program, Function function, Map<Address, int[]> wanted,
            TaskMonitor monitor) throws Exception {
        Map<Address, int[]> changes = new LinkedHashMap<>();
        for (var entry : wanted.entrySet()) {
            Address at = entry.getKey();
            if (contextValue(program, "c_load_mode", at) != entry.getValue()[0] ||
                    contextValue(program, "c_load_reg", at) != entry.getValue()[1]) {
                changes.put(at, entry.getValue());
            }
        }
        for (String name : C6000PacketContext.LOAD_FIELDS) {
            var ranges = program.getProgramContext().getRegisterValueAddressRanges(program.getRegister(name));
            while (ranges.hasNext()) {
                AddressRange range = ranges.next();
                for (Address at : new AddressSet(range).intersect(function.getBody()).getAddresses(true)) {
                    if (!wanted.containsKey(at) && contextValue(program, name, at) != 0) changes.put(at, new int[] { 0, 0 });
                }
            }
        }
        if (!changes.isEmpty()) refresh(program, changes, monitor);
    }

    private static void refresh(Program program, Map<Address, int[]> changes, TaskMonitor monitor)
            throws Exception {
        Listing listing = program.getListing();
        ReferenceManager references = program.getReferenceManager();
        List<SavedInstruction> savedInstructions = new ArrayList<>();
        List<SavedReference> savedReferences = new ArrayList<>();
        List<SavedComment> savedComments = new ArrayList<>();
        // Decode every change first, so nothing is cleared that cannot be laid again.
        for (var change : changes.entrySet()) {
            Instruction instruction = listing.getInstructionAt(change.getKey());
            if (instruction == null) continue;
            var context = new ProcessorContextImpl(program.getLanguage());
            var stored = program.getProgramContext().getRegisterValue(
                program.getLanguage().getContextBaseRegister(), change.getKey());
            if (stored != null) context.setRegisterValue(stored);
            for (int k = 0; k < 2; k++) setContext(context, program, C6000PacketContext.LOAD_FIELDS.get(k), change.getValue()[k]);
            setContext(context, program, "c_pkt_active", active(program, change.getKey(), change.getValue()[0]));
            var prototype = program.getLanguage().parse(new DumbMemBufferImpl(program.getMemory(), change.getKey()), context, false);
            if (prototype.getLength() != instruction.getLength()) throw new IllegalStateException("deferral changes the width at " + change.getKey());
        }
        for (Address changed : changes.keySet()) {
            Instruction instruction = listing.getInstructionAt(changed);
            if (instruction == null) continue;
            Address start = instruction.getMinAddress();
            Address end = instruction.getMaxAddress();
            savedInstructions.add(new SavedInstruction(start, instruction.getLength(),
                instruction.getFlowOverride(), instruction.isFallThroughOverridden(),
                instruction.getFallThrough()));
            for (Address at = start; at.compareTo(end) <= 0; at = at.next()) {
                for (int type = 0; type < 5; type++) {
                    String comment = listing.getComment(type, at);
                    if (comment != null) savedComments.add(new SavedComment(at, type, comment));
                }
                for (Reference reference : references.getReferencesFrom(at)) {
                    savedReferences.add(new SavedReference(reference, reference.isPrimary(),
                        reference.getSymbolID()));
                }
            }
            listing.clearCodeUnits(start, end, false);
        }
        for (var change : changes.entrySet()) {
            monitor.checkCancelled();
            int active = active(program, change.getKey(), change.getValue()[0]);
            for (int k = 0; k < 2; k++) {
                program.getProgramContext().setValue(program.getRegister(C6000PacketContext.LOAD_FIELDS.get(k)),
                    change.getKey(), change.getKey(), BigInteger.valueOf(change.getValue()[k]));
            }
            program.getProgramContext().setValue(program.getRegister("c_pkt_active"), change.getKey(),
                change.getKey(), BigInteger.valueOf(active));
        }
        Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
        for (SavedInstruction saved : savedInstructions) {
            disassembler.disassemble(saved.address(),
                new AddressSet(saved.address(), saved.address().add(saved.length() - 1)), false);
            Instruction replacement = listing.getInstructionAt(saved.address());
            if (replacement == null) throw new IllegalStateException("re-decode failed at " + saved.address());
            if (saved.override() != FlowOverride.NONE) replacement.setFlowOverride(saved.override());
            if (saved.fallThroughOverridden()) replacement.setFallThrough(saved.fallThrough());
        }
        for (SavedComment saved : savedComments) listing.setComment(saved.address(), saved.type(), saved.comment());
        for (SavedReference saved : savedReferences) {
            Reference reference = saved.reference();
            Reference restored = reference.isRegisterReference()
                ? references.addRegisterReference(reference.getFromAddress(),
                    reference.getOperandIndex(), program.getRegister(reference.getToAddress()),
                    reference.getReferenceType(), reference.getSource())
                : references.addReference(reference);
            references.setPrimary(restored, saved.primary());
            var symbol = program.getSymbolTable().getSymbol(saved.symbolId());
            if (symbol != null) references.setAssociation(symbol, restored);
        }
    }
}
