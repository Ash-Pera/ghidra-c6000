// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Lossless encoding-form metadata for exporters and assembler oracles.
 *
 * <p>A TI-compatible mnemonic alone cannot distinguish all C6000 encodings.
 * In particular, small B14/B15 offsets can use either the short-five-bit or
 * long-fifteen-bit address form. This describes that choice without inventing
 * an assembler suffix or changing disassembly semantics. See SPRUFE8B 3.9.3,
 * 3.10.2, and the 3.12 ADDAW and scalar load/store opcode maps.
 */
public final class C6000EncodingInfo {
    public enum AddressForm { NONE, COMPACT, SHORT5, LONG15, REGISTER }

    /** Numeric header fields retain all packet expansion and compact p bits. */
    public record PacketHeader(long address, boolean readable, boolean headerBased,
            Integer layout, Integer expansion, Integer compactParallelBits) { }

    /**
     * The offset is the encoded element count, not a byte displacement.
     * Null fields mean not applicable or (for BNOP scale) unavailable context.
     */
    public record Encoding(int instructionWidth, String operation, AddressForm addressForm,
            String baseRegister, Integer encodedOffset, String offsetRegister,
            Integer offsetScaleBytes, Integer predicateRegister, Boolean predicateInverted,
            Boolean parallelNext, Integer pcRelativeScaleBytes, Integer addressMode,
            Boolean crossPath, PacketHeader packet) { }

    private static final Set<String> SCALAR_MEMORY =
        Set.of("LDB", "LDBU", "LDH", "LDHU", "LDW", "STB", "STH", "STW");
    private static final Set<String> ADDRESS_ADD = Set.of("ADDAB", "ADDAH", "ADDAW");

    private C6000EncodingInfo() { }

    private static int word(byte[] bytes, Program program) {
        return ByteBuffer.wrap(bytes).order(program.getLanguage().isBigEndian()
            ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private static PacketHeader packet(Instruction instruction) {
        Program program = instruction.getProgram();
        long offset = instruction.getAddress().getOffset() & ~31L;
        try {
            Address end = instruction.getAddress().getNewAddress(offset + 28);
            byte[] bytes = new byte[4];
            if (program.getMemory().getBytes(end, bytes) != 4) {
                return new PacketHeader(offset, false, false, null, null, null);
            }
            int header = word(bytes, program);
            if ((header >>> 28) != 14) {
                return new PacketHeader(offset, true, false, null, null, null);
            }
            return new PacketHeader(offset, true, true, (header >>> 21) & 127,
                (header >>> 14) & 127, header & 0x3fff);
        }
        catch (MemoryAccessException | IllegalArgumentException e) {
            return new PacketHeader(offset, false, false, null, null, null);
        }
    }

    /**
     * Source of an unconditional register copy, including either explicit zero
     * operand of integer ADD/OR. This keeps constant-recovery clients independent
     * of pseudo-mnemonic choice (SPRUFE8B 3.12 MV, ADD and OR).
     */
    public static Register registerCopySource(Instruction instruction) {
        String mnemonic = instruction.getMnemonicString();
        if (mnemonic.startsWith("[")) return null;
        String operation = mnemonic.split("\\.", 2)[0];
        int n = instruction.getNumOperands();
        if (operation.equals("MV") && n == 2) return instruction.getRegister(0);
        if ((operation.equals("ADD") || operation.equals("OR")) && n == 3) {
            for (int zero = 0; zero < 2; zero++) {
                var scalar = instruction.getScalar(zero);
                if (scalar != null && scalar.getValue() == 0) {
                    return instruction.getRegister(1 - zero);
                }
            }
        }
        return null;
    }

    // Only the scalar move-primitive maps are identified here. Elsewhere bit 12
    // may be an opcode/immediate bit; unknown cross-path identity stays null.
    private static Boolean scalarMoveCrossPath(int bits) {
        if ((bits & 0x3e000) != 0) return null;
        int low = bits & 0xffc;
        if (low == 0x58 || low == 0xfd8 || low == 0x1a0 || low == 0x8f0) {
            return (bits & 0x1000) != 0;
        }
        if ((bits & 0x1ffc) == 0x940) return false;
        return null;
    }

    public static Encoding describe(Instruction instruction) throws MemoryAccessException {
        if (!C6000PacketContext.isC6000(instruction.getProgram())) {
            throw new IllegalArgumentException("C6000 instruction required");
        }
        String mnemonic = instruction.getMnemonicString().replaceFirst("^\\[[^]]+\\]", "");
        String operation = mnemonic.split("\\.", 2)[0];
        int width = instruction.getLength();
        PacketHeader packet = packet(instruction);
        if (operation.equals("CPKT")) {
            // SPRUFE8B 3.10.2: a header is metadata, not a predicated opcode.
            return new Encoding(width, operation, AddressForm.NONE, null, null,
                null, null, null, null, null, null, null, null, packet);
        }
        if (width != 4) {
            return new Encoding(width, operation, AddressForm.COMPACT, null, null,
                null, null, null, null, null, null, null, null, packet);
        }
        int bits = word(instruction.getBytes(), instruction.getProgram());
        int predicate = bits >>> 29;
        boolean inverted = (bits & 0x10000000) != 0;
        AddressForm form = AddressForm.NONE;
        String base = null, offsetRegister = null;
        Integer offset = null, scale = null, pcScale = null, addressMode = null;
        Boolean cross = scalarMoveCrossPath(bits);
        if (SCALAR_MEMORY.contains(operation)) {
            scale = operation.endsWith("W") ? 4 :
                (operation.equals("LDH") || operation.equals("LDHU") || operation.equals("STH")) ? 2 : 1;
            if ((bits & 12) == 12) {
                form = AddressForm.LONG15;
                base = "B" + (14 + ((bits >>> 7) & 1));
                offset = (bits >>> 8) & 0x7fff;
            }
            else {
                addressMode = (bits >>> 9) & 15;
                String bank = (bits & 128) == 0 ? "A" : "B";
                base = bank + ((bits >>> 18) & 31);
                if ((bits & (4 << 9)) == 0) {
                    form = AddressForm.SHORT5;
                    offset = (bits >>> 13) & 31;
                }
                else {
                    form = AddressForm.REGISTER;
                    offsetRegister = bank + ((bits >>> 13) & 31);
                }
            }
        }
        else if (ADDRESS_ADD.contains(operation)) {
            scale = operation.equals("ADDAW") ? 4 : operation.equals("ADDAH") ? 2 : 1;
            // SPRUFE8B 3.12 ADDAW: the long address-add family has no predicate.
            if ((bits >>> 28) == 1 && (bits & 12) == 12) {
                form = AddressForm.LONG15;
                base = "B" + (14 + ((bits >>> 7) & 1));
                offset = (bits >>> 8) & 0x7fff;
                predicate = 0;
                inverted = false;
            }
            else {
                String bank = (bits & 2) == 0 ? "A" : "B";
                base = bank + ((bits >>> 18) & 31);
                if ((bits & 256) != 0) {
                    form = AddressForm.SHORT5;
                    offset = (bits >>> 13) & 31;
                }
                else {
                    form = AddressForm.REGISTER;
                    offsetRegister = bank + ((bits >>> 13) & 31);
                }
            }
        }
        // Only full32 BNOP changes displacement units in a header-based packet.
        // B, BDEC and BPOS remain word-scaled (SPRUFE8B 3.12 execution blocks).
        if (operation.equals("BNOP") && !instruction.getFlowType().isComputed()) {
            pcScale = packet.readable() ? (packet.headerBased() ? 2 : 4) : null;
        }
        else if (Set.of("B", "BDEC", "BPOS", "CALLP", "ADDKPC").contains(operation)
                && !instruction.getFlowType().isComputed()) {
            pcScale = 4;
        }
        return new Encoding(width, operation, form, base, offset, offsetRegister, scale,
            predicate, inverted, (bits & 1) != 0, pcScale, addressMode, cross, packet);
    }
}
