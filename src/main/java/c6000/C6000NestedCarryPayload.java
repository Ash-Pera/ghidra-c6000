// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public final class C6000NestedCarryPayload extends InjectPayloadCallother {
    static final String OPTIONS = "C6000 Nested Delay Carries";

    public C6000NestedCarryPayload(String source) {
        super(source);
    }

    static String key(ghidra.program.model.address.Address at) {
        return "carry." + Long.toUnsignedString(at.getOffset(), 16);
    }

    @Override
    public boolean isFallThru() {
        return true;
    }

    @Override
    public PcodeOp[] getPcode(Program program, InjectContext context) throws IOException {
        String encoded = program.getOptions(OPTIONS).getString(key(context.baseAddr), "");
        if (encoded.isBlank()) throw new IOException("Nested carry has no action at " + context.baseAddr);
        var carrier = program.getListing().getInstructionAt(context.baseAddr);
        PcodeOp[] base = carrier == null ? new PcodeOp[0] : carrier.getPcode();
        int start = -1;
        for (PcodeOp op : base) {
            if (op.getOpcode() == PcodeOp.CALLOTHER) {
                start = op.getSeqnum().getTime();
                break;
            }
        }
        if (start < 0) throw new IOException("Nested carry has no callother at " + context.baseAddr);
        var constant = program.getAddressFactory().getConstantSpace();
        var unique = program.getAddressFactory().getUniqueSpace();
        var link = new Varnode(program.getRegister("B3").getAddress(), 4);
        List<PcodeOp> ops = new ArrayList<>();
        long temp = 0x10000000L;
        for (String action : encoded.split(";")) {
            String[] fields = action.split(",", -1);
            boolean call = fields.length == 3 && fields[0].equals("C");
            boolean returns = fields.length == 2 && fields[0].equals("R");
            if ((!call && !returns) || !fields[1].matches("!?[AB][0-9]{1,2}"))
                throw new IOException("Invalid nested carry action at " + context.baseAddr);
            var guard = program.getRegister(fields[1].replace("!", ""));
            if (guard == null) throw new IOException("Unknown nested carry guard " + fields[1]);
            int index = ops.size();
            var skip = new Varnode(unique.getAddress(temp), 1);
            temp += 16;
            boolean inverted = fields[1].startsWith("!");
            int test = inverted ? PcodeOp.INT_NOTEQUAL : PcodeOp.INT_EQUAL;
            ops.add(new PcodeOp(context.baseAddr, start + index, test, new Varnode[] {
                new Varnode(guard.getAddress(), 4), new Varnode(constant.getAddress(0), 4)
            }, skip));
            int branchIndex = ops.size();
            ops.add(new PcodeOp(context.baseAddr, start + branchIndex, PcodeOp.CBRANCH,
                new Varnode[] { new Varnode(constant.getAddress(0), 4), skip }, null));
            if (call) {
                long offset;
                try {
                    offset = Long.parseUnsignedLong(fields[2], 16);
                }
                catch (NumberFormatException e) {
                    throw new IOException("Invalid nested carry target at " + context.baseAddr, e);
                }
                var target = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
                ops.add(new PcodeOp(context.baseAddr, start + ops.size(), PcodeOp.CALL,
                    new Varnode[] { new Varnode(target, 4) }, null));
            }
            ops.add(new PcodeOp(context.baseAddr, start + ops.size(), PcodeOp.RETURN, new Varnode[] { link }, null));
            int after = ops.size();
            ops.get(branchIndex).setInput(new Varnode(constant.getAddress(after - branchIndex), 4), 0);
        }
        ops.add(new PcodeOp(context.baseAddr, start + ops.size(), PcodeOp.COPY, new Varnode[] {
            new Varnode(constant.getAddress(0), 1)
        }, new Varnode(unique.getAddress(temp), 1)));
        return ops.toArray(PcodeOp[]::new);
    }
}
