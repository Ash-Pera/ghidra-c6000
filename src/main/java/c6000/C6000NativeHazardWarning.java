// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds functions whose default per-instruction lifting is inexact because it does not
 * schedule result latency or branch windows (SPRUFE8B 3.5, 4.2.6): a load result read
 * before it lands, or two branch windows in flight at once (software-pipelined loops,
 * nested windows). Reports a straight-line cycle timeline per packet; it follows fall-
 * through only, so it never asserts a hazard across an edge it cannot see.
 */
public final class C6000NativeHazardWarning {
    private static final int LOAD_LATENCY = 5;   // result readable 5 cycles after issue
    private static final int BRANCH_WINDOW = 6;  // transfer 6 cycles after issue (Table 4-11)

    public record Finding(Address at, String reason) {}

    private record Packet(Address start, List<Instruction> members, int cycle, int length) {}

    private C6000NativeHazardWarning() {}

    /** The hazard, or null when native lifting is exact (or a schedule already covers it). */
    public static Finding scan(Program program, Function function) throws Exception {
        if (BigInteger.ONE.equals(program.getProgramContext().getValue(
                program.getRegister("c_schedule_entry"), function.getEntryPoint(), false))) {
            return null;
        }
        List<Packet> timeline = timeline(program, function);
        Finding branches = overlappingBranchWindows(timeline);
        if (branches != null) return branches;
        return unlandedLoad(program, timeline);
    }

    /** Straight-line execute packets of the body in address order, each with a start cycle. */
    private static List<Packet> timeline(Program program, Function function) throws Exception {
        var listing = program.getListing();
        List<Packet> packets = new ArrayList<>();
        int cycle = 0;
        Address at = function.getEntryPoint();
        Address end = function.getBody().getMaxAddress();
        Set<Address> seen = new LinkedHashSet<>();
        while (at != null && at.compareTo(end) <= 0 && function.getBody().contains(at)) {
            Instruction first = listing.getInstructionAt(at);
            if (first == null || !seen.add(at)) break;
            List<Instruction> members = new ArrayList<>();
            int span = 1;
            for (Address member : C6000ExecutionPackets.packetMembers(program, at)) {
                Instruction instruction = listing.getInstructionAt(member);
                if (instruction == null) break;
                members.add(instruction);
                span = Math.max(span, nopCycles(instruction));
            }
            if (members.isEmpty()) break;
            Address last = members.get(members.size() - 1).getAddress();
            packets.add(new Packet(at, members, cycle, span));
            cycle += span;
            at = last.add(C6000ExecutionPackets.instructionLengthAt(program, last));
        }
        return packets;
    }

    private static Finding overlappingBranchWindows(List<Packet> timeline) {
        List<int[]> branches = new ArrayList<>();  // {cycle, index}
        for (int i = 0; i < timeline.size(); i++) {
            for (Instruction instruction : timeline.get(i).members()) {
                if (branch(instruction)) branches.add(new int[] { timeline.get(i).cycle(), i });
            }
        }
        for (int i = 1; i < branches.size(); i++) {
            if (branches.get(i)[0] - branches.get(i - 1)[0] < BRANCH_WINDOW) {
                return new Finding(timeline.get(branches.get(i)[1]).start(),
                    "a branch issues while an earlier branch's delay window is in flight; "
                    + "native lifting orders its slots after the transfer (enable an exact schedule)");
            }
        }
        return null;
    }

    private static Finding unlandedLoad(Program program, List<Packet> timeline) throws Exception {
        for (int i = 0; i < timeline.size(); i++) {
            for (Instruction load : timeline.get(i).members()) {
                if (!op(load).startsWith("LD")) continue;
                Set<String> written = writes(program, load);
                if (written.isEmpty()) continue;
                int landCycle = timeline.get(i).cycle() + LOAD_LATENCY;
                for (int j = i; j < timeline.size(); j++) {
                    int cycle = timeline.get(j).cycle();
                    if (cycle >= landCycle) break;
                    for (Instruction later : timeline.get(j).members()) {
                        if (later.getAddress().equals(load.getAddress())) continue;
                        if (branch(later)) return null;  // a window we did not model; do not assert
                        var reads = reads(program, later);
                        for (String name : written) {
                            if (reads.contains(name)) {
                                return new Finding(later.getAddress(),
                                    "reads " + name + " before the load at " + load.getAddress()
                                    + " lands; native lifting exposes the loaded value early "
                                    + "(enable an exact schedule)");
                            }
                        }
                    }
                    // A plain (non-load) rewrite of the register ends the hazard for it.
                    for (Instruction later : timeline.get(j).members()) {
                        if (later.getAddress().equals(load.getAddress())) continue;
                        if (!op(later).startsWith("LD")) {
                            written.removeAll(writes(program, later));
                        }
                    }
                    if (written.isEmpty()) break;
                }
            }
        }
        return null;
    }

    /** Mnemonic without predicate or unit: "[A1] LDW.D1T1" -> "LDW", "B.S2" -> "B". */
    private static String op(Instruction instruction) {
        String name = C6000CallAnalyzer.baseName(instruction).trim();
        int unit = name.indexOf('.');
        return unit >= 0 ? name.substring(0, unit) : name;
    }

    private static boolean branch(Instruction instruction) {
        String name = op(instruction);
        return name.equals("B") || name.equals("BNOP") || name.equals("CALLP")
            || name.equals("BDEC") || name.equals("BPOS");
    }

    private static int nopCycles(Instruction instruction) {
        if (!op(instruction).equals("NOP")) return 1;
        var count = instruction.getScalar(0);
        return count != null && count.getUnsignedValue() > 1 ? (int) count.getUnsignedValue() : 1;
    }

    private static Set<String> reads(Program program, Instruction instruction) {
        Set<String> result = new LinkedHashSet<>();
        for (PcodeOp op : instruction.getPcode(false)) {
            for (Varnode input : op.getInputs()) result.addAll(gprs(program, input));
        }
        return result;
    }

    private static Set<String> writes(Program program, Instruction instruction) {
        Set<String> result = new LinkedHashSet<>();
        for (PcodeOp op : instruction.getPcode(false)) result.addAll(gprs(program, op.getOutput()));
        return result;
    }

    private static Set<String> gprs(Program program, Varnode node) {
        if (node == null || !node.isRegister() || !node.getAddress().getAddressSpace()
                .equals(program.getAddressFactory().getRegisterSpace())) return Set.of();
        var register = program.getRegister(node.getAddress(), node.getSize());
        if (register == null) register = program.getRegister(node.getAddress());
        String name = register == null ? null : register.getName();
        return name != null && name.length() >= 2 && (name.charAt(0) == 'A' || name.charAt(0) == 'B')
            && Character.isDigit(name.charAt(1)) ? Set.of(name) : Set.of();
    }
}
