/* ### */
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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.disassemble.Disassembler;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Stages only GPR writers whose values are read later in the same issue packet. */
final class C6000ParallelReadScheduler {
    private static final List<String> CONTEXT_FIELDS = C6000PacketContext.PACKET_FIELDS;
    private static final Set<String> GENERAL_REGISTERS = generalRegisters();

    record Result(int deferredPackets, int refusedPackets) {}

    private record Fields(int active, int start, int end, int branchEnd, int chain0,
            int chain1, int write0, int write1, int commit0, int commit1) {
        static Fields zero() { return new Fields(0, 0, 0, 0, 0, 0, 0, 0, 0, 0); }
    }

    private record Member(Address address, Set<String> reads, Set<String> writes,
            int predicate, boolean control, boolean branchCommitHook, boolean opaque) {}

    private record Plan(List<Address> members, List<Fields> fields, boolean deferred,
            boolean refused) {}

    private record TargetRange(AddressSpace space, long first, long end) {}

    private C6000ParallelReadScheduler() {}

    static Result prime(Program program, AddressSetView scope, TaskMonitor monitor)
            throws Exception {
        List<List<Address>> packets = physicalPackets(program, scope, monitor);
        Set<Address> flowTargets = flowTargets(program, monitor);
        List<Plan> plans = new ArrayList<>();
        int refused = 0;
        for (List<Address> members : packets) {
            monitor.checkCancelled();
            Plan plan = plan(program, members, monitor, flowTargets);
            if (plan.refused()) refused++;
            plans.add(plan);
        }

        for (Plan plan : plans) {
            for (int i = 0; i < plan.members().size(); i++) {
                setFields(program, plan.members().get(i), plan.fields().get(i));
            }
        }
        clearHeaders(program, scope);
        return new Result((int) plans.stream().filter(Plan::deferred).count(), refused);
    }

    static int audit(Program program, TaskMonitor monitor) throws Exception {
        if (!C6000PacketContext.isC6000(program)) return 0;
        int transaction = program.startTransaction("Audit C6000 parallel packet targets");
        boolean commit = false;
        try {
            AddressSetView initialized = program.getMemory().getAllInitializedAddressSet();
            AddressSet scope = fetchPackets(initialized);
            Set<Address> processed = new HashSet<>();
            List<List<Address>> starts = physicalPackets(program, scope, monitor);
            Set<Address> flowTargets = flowTargets(program, monitor);
            int refused = 0;
            for (List<Address> members : starts) {
                monitor.checkCancelled();
                if (!processed.add(members.get(0)) || !activeStart(program, members.get(0))) continue;
                List<TargetRange> unsafe = unsafeRanges(program, members);
                if (unsafe.isEmpty() ||
                        !hasIncomingTarget(program, unsafe, flowTargets, monitor)) continue;
                disablePacket(program, members, monitor);
                refused++;
            }
            commit = true;
            return refused;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
    }

    static void clearAt(Program program, Address address) throws Exception {
        setFields(program, address, Fields.zero());
    }

    private static Plan plan(Program program, List<Address> addresses, TaskMonitor monitor,
            Set<Address> flowTargets) throws Exception {
        if (addresses.size() == 1) return zeroPlan(addresses, false);
        List<Member> members = new ArrayList<>();
        try {
            for (Address address : addresses) members.add(analyze(program, address));
        }
        catch (UnknownInstructionException unsupported) {
            return zeroPlan(addresses, true);
        }

        Set<String> earlierWrites = new LinkedHashSet<>();
        Set<String> deferred = new LinkedHashSet<>();
        for (Member member : members) {
            for (String read : member.reads()) {
                if (earlierWrites.contains(read)) deferred.add(read);
            }
            earlierWrites.addAll(member.writes());
        }
        if (members.stream().anyMatch(Member::opaque)) return zeroPlan(addresses, true);
        if (deferred.isEmpty()) return zeroPlan(addresses, false);

        for (int i = 0; i < members.size(); i++) {
            long writerCount = members.get(i).writes().stream().filter(deferred::contains).count();
            if (writerCount > 2) return zeroPlan(addresses, true);
            if (members.get(i).predicate() < 0 && writerCount != 0) {
                return zeroPlan(addresses, true);
            }
            if (members.get(i).control() && i != members.size() - 1) {
                return zeroPlan(addresses, true);
            }
        }
        // The last member commits every staged register: at most two.
        if (deferred.size() > 2) return zeroPlan(addresses, true);
        Member last = members.get(members.size() - 1);
        boolean branchEnd = last.control();
        if (branchEnd && !last.branchCommitHook()) return zeroPlan(addresses, true);
        // A terminal branch commits before its delay slots, so it cannot stage its own writes.
        if (branchEnd && last.writes().stream().anyMatch(deferred::contains)) {
            return zeroPlan(addresses, true);
        }
        if (hasIncomingTarget(program,
                unsafeRanges(program, addresses, members, deferred), flowTargets, monitor)) {
            return zeroPlan(addresses, true);
        }

        List<String> commits = deferred.stream()
            .sorted(Comparator.comparingInt(C6000ParallelReadScheduler::selector)).toList();
        Set<String> staged = new HashSet<>();
        List<Fields> fields = new ArrayList<>();
        for (int i = 0; i < members.size(); i++) {
            Member member = members.get(i);
            List<String> writes = member.writes().stream().filter(deferred::contains)
                .sorted(Comparator.comparingInt(C6000ParallelReadScheduler::selector)).toList();
            int[] chain = new int[2];
            for (int slot = 0; slot < writes.size(); slot++) {
                if (!staged.contains(writes.get(slot))) continue;
                // A continuing writer reads the shadow in place of the register, predicate included.
                if (writes.get(slot).equals(predicateRegister(member.predicate()))) {
                    return zeroPlan(addresses, true);
                }
                chain[slot] = 1;
            }
            staged.addAll(writes);
            boolean final_ = i == members.size() - 1;
            fields.add(new Fields(1, i == 0 ? 1 : 0, final_ && !branchEnd ? 1 : 0,
                final_ && branchEnd ? 1 : 0, chain[0], chain[1],
                writes.isEmpty() ? 0 : selector(writes.get(0)),
                writes.size() < 2 ? 0 : selector(writes.get(1)),
                final_ ? selector(commits.get(0)) : 0,
                final_ && commits.size() > 1 ? selector(commits.get(1)) : 0));
        }
        return new Plan(List.copyOf(addresses), List.copyOf(fields), true, false);
    }

    private static Member analyze(Program program, Address address) throws Exception {
        Instruction instruction = parse(program, address, false);
        Set<String> reads = new LinkedHashSet<>();
        Set<String> writes = new LinkedHashSet<>();
        boolean opaque = false;
        for (PcodeOp operation : instruction.getPcode(false)) {
            if (operation.getOpcode() == PcodeOp.UNIMPLEMENTED) opaque = true;
            for (Varnode input : operation.getInputs()) reads.addAll(gprs(program, input));
            writes.addAll(gprs(program, operation.getOutput()));
        }
        String mnemonic = instruction.getMnemonicString();
        int predicate = predicate(mnemonic);
        boolean control = instruction.getFlowType().isJump() ||
            instruction.getFlowType().isCall() || instruction.getFlowType().isTerminal();
        boolean hook = control && branchCommitHook(program, address);
        return new Member(address, Set.copyOf(reads), Set.copyOf(writes),
            predicate, control, hook, opaque);
    }

    private static Instruction parse(Program program, Address address, boolean branchEnd)
            throws Exception {
        var context = new ProcessorContextImpl(program.getLanguage());
        for (var field : C6000PacketContext.physicalDecodeFields(program, address).entrySet()) {
            setContext(context, program, field.getKey(), field.getValue());
        }
        for (String name : List.of("c_flow_delay", "c_schedule_entry", "c_branch_terminal")) {
            setContext(context, program, name, 0);
        }
        for (String name : CONTEXT_FIELDS) setContext(context, program, name, 0);
        if (branchEnd) {
            setContext(context, program, "c_pkt_branch_end", 1);
            setContext(context, program, "c_pkt_commit0", selector("A0"));
        }
        var memory = new DumbMemBufferImpl(program.getMemory(), address);
        var prototype = program.getLanguage().parse(memory, context, false);
        var instruction = new PseudoInstruction(program, address, prototype, memory, context);
        if (instruction.getLength() != C6000ExecutionPackets.instructionLengthAt(program, address)) {
            throw new IllegalArgumentException("physical decode width mismatch at " + address);
        }
        return instruction;
    }

    /** True if the branch, decoded as a packet's last member, commits staged registers. */
    private static boolean branchCommitHook(Program program, Address address) throws Exception {
        Instruction branch = parse(program, address, true);
        Register shadow = program.getRegister("C6000_PKT_A0");
        for (PcodeOp operation : branch.getPcode(false)) {
            for (Varnode input : operation.getInputs()) {
                if (input.isRegister() &&
                        input.getAddress().equals(shadow.getAddress())) return true;
            }
        }
        return false;
    }

    private static Set<String> gprs(Program program, Varnode node) {
        if (node == null || !node.isRegister() ||
                !node.getAddress().getAddressSpace().equals(
                    program.getAddressFactory().getRegisterSpace())) return Set.of();
        long start = node.getOffset();
        long end = start + node.getSize();
        Set<String> result = new LinkedHashSet<>();
        for (String name : GENERAL_REGISTERS) {
            Register register = program.getRegister(name);
            long registerStart = register.getAddress().getOffset();
            long registerEnd = registerStart + register.getMinimumByteSize();
            if (start < registerEnd && registerStart < end) result.add(name);
        }
        return result;
    }

    private static Set<String> generalRegisters() {
        Set<String> result = new LinkedHashSet<>();
        for (String bank : List.of("A", "B")) {
            for (int index = 0; index < 32; index++) result.add(bank + index);
        }
        return Set.copyOf(result);
    }

    private static int selector(String name) {
        int index = Integer.parseInt(name.substring(1));
        return (name.charAt(0) == 'A' ? 0 : 32) + index + 1;
    }

    private static String predicateRegister(int predicate) {
        return switch (predicate) {
            case 2, 3 -> "B0";
            case 4, 5 -> "B1";
            case 6, 7 -> "B2";
            case 8, 9 -> "A1";
            case 10, 11 -> "A2";
            case 12, 13 -> "A0";
            default -> null;
        };
    }

    private static int predicate(String mnemonic) {
        if (!mnemonic.startsWith("[")) return 0;
        int close = mnemonic.indexOf(']');
        if (close < 0) return -1;
        String name = mnemonic.substring(1, close);
        boolean inverted = name.startsWith("!");
        if (inverted) name = name.substring(1);
        int positive = switch (name) {
            case "B0" -> 2;
            case "B1" -> 4;
            case "B2" -> 6;
            case "A1" -> 8;
            case "A2" -> 10;
            case "A0" -> 12;
            default -> -1;
        };
        return positive < 0 ? -1 : positive + (inverted ? 1 : 0);
    }

    private static Plan zeroPlan(List<Address> addresses, boolean refused) {
        List<Fields> fields = new ArrayList<>();
        for (int i = 0; i < addresses.size(); i++) fields.add(Fields.zero());
        return new Plan(List.copyOf(addresses), List.copyOf(fields), false, refused);
    }

    private static List<List<Address>> physicalPackets(Program program, AddressSetView scope,
            TaskMonitor monitor) throws Exception {
        List<List<Address>> result = new ArrayList<>();
        Set<Address> seen = new HashSet<>();
        for (AddressRange range : scope.getAddressRanges()) {
            long last = range.getMaxAddress().getOffset() & ~31L;
            for (long offset = range.getMinAddress().getOffset() & ~31L;
                    offset <= last; offset += C6000PacketContext.FETCH_PACKET_SIZE) {
                monitor.checkCancelled();
                Address base = range.getAddressSpace().getAddressInThisSpaceOnly(offset);
                List<Address> candidates;
                try {
                    candidates = C6000ExecutionPackets.instructionStarts(program, base);
                }
                catch (MemoryAccessException incompleteFetch) {
                    continue;
                }
                for (Address candidate : candidates) {
                    List<Address> prefix;
                    List<Address> members;
                    try {
                        prefix = C6000ExecutionPackets.issuePrefix(program, candidate);
                        Address start = prefix.isEmpty() ? candidate : prefix.get(0);
                        if (!seen.add(start)) continue;
                        members = C6000ExecutionPackets.packetMembers(program, start);
                    }
                    catch (MemoryAccessException incomplete) {
                        continue;
                    }
                    if (members.stream().anyMatch(scope::contains)) result.add(members);
                }
            }
        }
        return result;
    }

    private static void setFields(Program program, Address address, Fields fields)
            throws Exception {
        int[] values = { fields.active(), fields.start(), fields.end(), fields.branchEnd(),
            fields.chain0(), fields.chain1(), fields.write0(), fields.write1(),
            fields.commit0(), fields.commit1() };
        for (int i = 0; i < CONTEXT_FIELDS.size(); i++) {
            Register register = program.getRegister(CONTEXT_FIELDS.get(i));
            BigInteger wanted = BigInteger.valueOf(values[i]);
            BigInteger current = program.getProgramContext().getValue(register, address, false);
            if (wanted.equals(current) || (wanted.signum() == 0 && current == null)) continue;
            program.getProgramContext().setValue(register, address, address, wanted);
        }
    }

    private static void setContext(ProcessorContextImpl context, Program program, String name,
            int value) {
        context.setRegisterValue(new RegisterValue(program.getRegister(name),
            BigInteger.valueOf(value)));
    }

    private static void clearHeaders(Program program, AddressSetView scope) throws Exception {
        var memory = program.getMemory();
        for (AddressRange range : scope.getAddressRanges()) {
            long last = range.getMaxAddress().getOffset() & ~31L;
            for (long offset = range.getMinAddress().getOffset() & ~31L;
                    offset <= last; offset += C6000PacketContext.FETCH_PACKET_SIZE) {
                Address base = range.getAddressSpace().getAddressInThisSpaceOnly(offset);
                Address header = base.add(28);
                if (!memory.getAllInitializedAddressSet().contains(header, header.add(3)) ||
                        (memory.getInt(header) >>> 28) != 0xe) continue;
                clearAt(program, header);
            }
        }
    }

    private static AddressSet fetchPackets(AddressSetView addresses) {
        AddressSet result = new AddressSet();
        for (AddressRange range : addresses.getAddressRanges()) {
            if (!range.getAddressSpace().isLoadedMemorySpace()) continue;
            var space = range.getAddressSpace();
            result.add(space.getAddressInThisSpaceOnly(range.getMinAddress().getOffset() & ~31L),
                space.getAddressInThisSpaceOnly((range.getMaxAddress().getOffset() & ~31L) + 31));
        }
        return result;
    }

    private static List<TargetRange> unsafeRanges(Program program, List<Address> addresses)
            throws Exception {
        List<TargetRange> ranges = new ArrayList<>();
        int last = addresses.size() - 1;
        long end = addresses.get(last).getOffset() +
            C6000ExecutionPackets.instructionLengthAt(program, addresses.get(last));
        for (int i = 0; i < last; i++) {
            Address address = addresses.get(i);
            int first = contextValue(program, "c_pkt_write0", address);
            int second = contextValue(program, "c_pkt_write1", address);
            if (first == 0 && second == 0) continue;
            long start = address.getOffset() + 1;
            if (start < end) ranges.add(new TargetRange(address.getAddressSpace(), start, end));
        }
        return ranges;
    }

    private static List<TargetRange> unsafeRanges(Program program, List<Address> addresses,
            List<Member> members, Set<String> deferred) throws Exception {
        List<TargetRange> ranges = new ArrayList<>();
        int last = addresses.size() - 1;
        long end = addresses.get(last).getOffset() +
            C6000ExecutionPackets.instructionLengthAt(program, addresses.get(last));
        for (int i = 0; i < last; i++) {
            if (members.get(i).writes().stream().noneMatch(deferred::contains)) continue;
            long start = addresses.get(i).getOffset() + 1;
            if (start < end) ranges.add(new TargetRange(addresses.get(i).getAddressSpace(),
                start, end));
        }
        return ranges;
    }

    private static int contextValue(Program program, String name, Address address) {
        BigInteger value = program.getProgramContext().getValue(program.getRegister(name),
            address, false);
        return value == null ? 0 : value.intValue();
    }

    private static boolean activeStart(Program program, Address address) {
        return contextValue(program, "c_pkt_active", address) != 0 &&
            contextValue(program, "c_pkt_start", address) != 0;
    }

    private static Set<Address> flowTargets(Program program, TaskMonitor monitor)
            throws CancelledException {
        Set<Address> targets = new HashSet<>();
        var instructions = program.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            if (!instruction.getFlowType().isJump() && !instruction.getFlowType().isCall()) continue;
            for (Address target : instruction.getFlows()) {
                if (target != null && !target.equals(instruction.getFallThrough())) {
                    targets.add(target);
                }
            }
        }
        return targets;
    }

    private static boolean hasIncomingTarget(Program program, List<TargetRange> ranges,
            Set<Address> flowTargets, TaskMonitor monitor) throws Exception {
        if (ranges.isEmpty()) return false;
        ReferenceManager references = program.getReferenceManager();
        for (TargetRange range : ranges) {
            for (long offset = range.first(); offset < range.end(); offset++) {
                monitor.checkCancelled();
                Address target = range.space().getAddressInThisSpaceOnly(offset);
                if (flowTargets.contains(target)) return true;
                for (Reference reference : references.getReferencesTo(target)) {
                    if (reference.getReferenceType().isFlow() &&
                            !reference.getReferenceType().isFallthrough()) return true;
                }
                if (program.getFunctionManager().getFunctionAt(target) != null) return true;
            }
        }
        return false;
    }

    private static void disablePacket(Program program, List<Address> members, TaskMonitor monitor)
            throws Exception {
        Listing listing = program.getListing();
        Map<Address, Instruction> codeUnits = new LinkedHashMap<>();
        for (Address member : members) {
            Instruction instruction = listing.getInstructionContaining(member);
            if (instruction != null) codeUnits.put(instruction.getAddress(), instruction);
        }
        List<SavedInstruction> savedInstructions = new ArrayList<>();
        List<SavedReference> savedReferences = new ArrayList<>();
        List<SavedComment> savedComments = new ArrayList<>();
        AddressSet clear = new AddressSet();
        for (Instruction instruction : codeUnits.values()) {
            Address start = instruction.getMinAddress();
            Address end = instruction.getMaxAddress();
            clear.add(start, end);
            savedInstructions.add(new SavedInstruction(start, instruction.getFlowOverride(),
                instruction.isFallThroughOverridden(), instruction.getFallThrough()));
            for (Address at = start; at.compareTo(end) <= 0; at = at.next()) {
                for (int type = 0; type < 5; type++) {
                    String comment = listing.getComment(type, at);
                    if (comment != null) savedComments.add(new SavedComment(at, type, comment));
                }
                for (Reference reference : program.getReferenceManager().getReferencesFrom(at)) {
                    savedReferences.add(new SavedReference(reference, reference.isPrimary(),
                        reference.getSymbolID()));
                }
            }
        }
        for (AddressRange range : clear.getAddressRanges()) {
            listing.clearCodeUnits(range.getMinAddress(), range.getMaxAddress(), false);
        }
        long first = members.get(0).getOffset() & ~1L;
        long end = members.get(members.size() - 1).getOffset() +
            C6000ExecutionPackets.instructionLengthAt(program, members.get(members.size() - 1));
        for (long offset = first; offset < end; offset += 2) {
            Address at = members.get(0).getAddressSpace().getAddressInThisSpaceOnly(offset);
            if (listing.getInstructionContaining(at) == null) clearAt(program, at);
        }

        Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
        for (SavedInstruction saved : savedInstructions) {
            int width = C6000ExecutionPackets.instructionLengthAt(program, saved.address());
            Address last = saved.address().add(width - 1);
            disassembler.disassemble(saved.address(), new AddressSet(saved.address(), last), false);
            Instruction replacement = listing.getInstructionAt(saved.address());
            if (replacement != null) {
                if (saved.override() != FlowOverride.NONE) replacement.setFlowOverride(saved.override());
                if (saved.fallThroughOverridden()) replacement.setFallThrough(saved.fallThrough());
            }
        }
        for (SavedComment saved : savedComments) {
            listing.setComment(saved.address(), saved.type(), saved.comment());
        }
        for (SavedReference saved : savedReferences) {
            Reference reference = saved.reference();
            Reference restored = reference.isRegisterReference()
                ? program.getReferenceManager().addRegisterReference(reference.getFromAddress(),
                    reference.getOperandIndex(), program.getRegister(reference.getToAddress()),
                    reference.getReferenceType(), reference.getSource())
                : program.getReferenceManager().addReference(reference);
            program.getReferenceManager().setPrimary(restored, saved.primary());
            var symbol = program.getSymbolTable().getSymbol(saved.symbolId());
            if (symbol != null) program.getReferenceManager().setAssociation(symbol, restored);
        }
    }

    private record SavedInstruction(Address address, FlowOverride override,
            boolean fallThroughOverridden, Address fallThrough) {}
    private record SavedReference(Reference reference, boolean primary, long symbolId) {}
    private record SavedComment(Address address, int type, String comment) {}
}
