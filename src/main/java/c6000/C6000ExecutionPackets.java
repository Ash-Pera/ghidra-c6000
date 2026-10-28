// SPDX-License-Identifier: Apache-2.0
package c6000;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/** Physical packet boundaries, SPRUFE8B 3.5 and 3.10.2.3 / Table 3-16. */
public final class C6000ExecutionPackets {
    private C6000ExecutionPackets() { }

    public static boolean parallelWithNext(Program program, Instruction instruction)
            throws MemoryAccessException {
        Address at = instruction.getAddress();
        if (instruction.getLength() == 4) return (program.getMemory().getInt(at) & 1) != 0;
        long base = at.getOffset() & ~31L;
        int header = program.getMemory().getInt(at.getNewAddress(base + 28));
        if ((header >>> 28) != 0xe) throw new MemoryAccessException("No compact header");
        return ((header >>> ((at.getOffset() - base) / 2)) & 1) != 0;
    }

    /** PROT adds four NOP cycles to either load width: SPRUFE8B 3.10.2.2. */
    static boolean protectedLoad(Program program, Instruction instruction)
            throws MemoryAccessException {
        if (!C6000CallAnalyzer.baseName(instruction).startsWith("LD")) return false;
        long base = instruction.getAddress().getOffset() & ~31L;
        Address at = instruction.getAddress().getNewAddress(base + 28);
        if (!program.getMemory().contains(at.add(3))) return false;
        int header = program.getMemory().getInt(at);
        return (header >>> 28) == 0xe && (header & (1 << 20)) != 0;
    }

    /** Minimal physical instruction shape; headers occupy bytes but no execute cycle. */
    private record Slot(Address at, int length, boolean parallel, boolean header) { }

    private static Slot slot(Program program, Address at) throws MemoryAccessException {
        var memory = program.getMemory();
        long base = at.getOffset() & ~31L;
        int offset = (int) (at.getOffset() - base);
        if ((offset & 1) != 0) throw new MemoryAccessException("Odd instruction address");
        Address ha = at.getNewAddress(base + 28);
        var block = memory.getBlock(at);
        if (block == null || !block.isInitialized()) throw new MemoryAccessException("Uninitialized code");
        boolean compactPacket = false;
        int header = 0;
        if (memory.contains(ha.add(3))) {
            header = memory.getInt(ha);
            compactPacket = (header >>> 28) == 0xe;
        }
        if (compactPacket && offset == 28) return new Slot(at, 4, false, true);
        boolean compact = compactPacket && ((header >>> (21 + offset / 4)) & 1) != 0;
        if (!compact && (offset & 3) != 0) throw new MemoryAccessException("Not an instruction boundary");
        int length = compact ? 2 : 4;
        if (!memory.contains(at.add(length - 1))) throw new MemoryAccessException("Truncated instruction");
        boolean parallel = compact ? ((header >>> (offset / 2)) & 1) != 0 :
            (memory.getInt(at) & 1) != 0;
        return new Slot(at, length, parallel, false);
    }

    /** Bytes after this instruction through its execute-packet end, including crossed headers. */
    public static int parallelBytes(Program program, Address at) throws MemoryAccessException {
        Slot current = slot(program, at);
        if (current.header()) return 0;
        Address firstEnd = at.add(current.length());
        int instructions = 1;
        while (current.parallel()) {
            if (++instructions > 8) throw new MemoryAccessException("Oversized execute packet");
            Slot next = slot(program, current.at().add(current.length()));
            if (next.header()) next = slot(program, next.at().add(next.length()));
            current = next;
        }
        return (int) (current.at().add(current.length()).subtract(firstEnd));
    }
}
