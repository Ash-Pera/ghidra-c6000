// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B Figure G-3: predicate polarity, fixed-low predicates, and aliased writes.
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import com.google.gson.Gson;
import c6000.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;

public class C6000CompactPredicatedMvkTest extends GhidraScript {
    static class Case {
        String mnemonic, predicate_register, destination, shadow;
        int immediate;
        long[][] checks;
    }
    static final long SENTINEL = 0x13579bdfL, SHADOW = 0x2468ace0L, RETURN = 0x9000L;

    void equal(long expected, long actual, String label) {
        if (expected != (actual & 0xffffffffL)) {
            throw new AssertionError(label + " expected=0x" + Long.toHexString(expected) +
                " actual=0x" + Long.toHexString(actual));
        }
    }
    Map<String, Long> inputs(Case c, long predicate) {
        var values = new LinkedHashMap<String, Long>();
        // The unselected predicate has the opposite truth value. A wrong
        // register or an erroneous RS-dependent predicate cannot pass by luck.
        values.put("A0", predicate == 0 ? 1L : 0L);
        values.put("B0", predicate == 0 ? 1L : 0L);
        values.put(c.destination, SENTINEL);
        values.put(c.predicate_register, predicate);
        values.put(c.shadow, SHADOW);
        values.put("AMR", 0L);
        values.put("CSR", 0x2468L);
        values.put("B3", RETURN);
        return values;
    }
    void raw(Case c, long[] check, ghidra.program.model.address.Address address) throws Exception {
        var emulator = new EmulatorHelper(currentProgram);
        try {
            var inputs = inputs(c, check[0]);
            for (var input : inputs.entrySet()) emulator.writeRegister(input.getKey(), input.getValue());
            var context = currentProgram.getRegister("contextreg");
            BigInteger value = currentProgram.getProgramContext().getValue(context, address, false);
            if (value != null) emulator.setContextRegister(context, value);
            emulator.getEmulator().setExecuteAddress(address.getOffset());
            if (!emulator.step(monitor)) throw new AssertionError(emulator.getLastError());
            equal(check[1], emulator.readRegister(c.destination).longValue(), address + " raw destination");
            for (String name : List.of("A0", "B0", c.shadow, "CSR", "B3")) {
                if (!name.equals(c.destination)) equal(inputs.get(name), emulator.readRegister(name).longValue(),
                    address + " raw preserved " + name);
            }
        } finally { emulator.dispose(); }
    }
    void scheduled(Case c, long[] check, PcodeProgram code) throws Exception {
        var language = (SleighLanguage) currentProgram.getLanguage();
        var arithmetic = BytesPcodeArithmetic.forLanguage(language);
        var reason = PcodeExecutorStatePiece.Reason.INSPECT;
        var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
        state.setVar(currentProgram.getAddressFactory().getRegisterSpace().getAddress(0),
            0x2100, false, new byte[0x2100]);
        var inputs = inputs(c, check[0]);
        for (var input : inputs.entrySet()) state.setVar(currentProgram.getRegister(input.getKey()),
            arithmetic.fromConst(input.getValue(), 4));
        var executor = new PcodeExecutor<byte[]>(language, arithmetic, state,
            PcodeExecutorStatePiece.Reason.EXECUTE_READ);
        var library = PcodeUseropLibrary.<byte[]>nil();
        var frame = executor.begin(code);
        int steps = 0;
        while (!frame.isFinished() && steps++ < 10000) executor.step(frame, library);
        if (!frame.isFinished()) throw new AssertionError("Schedule did not return: " + c.mnemonic);
        equal(check[1], arithmetic.toLong(state.getVar(currentProgram.getRegister(c.destination), reason),
            PcodeArithmetic.Purpose.INSPECT), c.mnemonic + " scheduled destination");
        for (String name : List.of("A0", "B0", c.shadow, "CSR", "B3")) {
            if (!name.equals(c.destination)) equal(inputs.get(name),
                arithmetic.toLong(state.getVar(currentProgram.getRegister(name), reason),
                    PcodeArithmetic.Purpose.INSPECT), c.mnemonic + " scheduled preserved " + name);
        }
        equal(RETURN, arithmetic.toLong(state.getVar(currentProgram.getRegister("PC"), reason),
            PcodeArithmetic.Purpose.INSPECT), c.mnemonic + " return PC");
    }
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("expected cases.json");
        Case[] cases = new Gson().fromJson(Files.readString(Paths.get(getScriptArgs()[0])), Case[].class);
        C6000PacketContext.prime(currentProgram, monitor);
        var language = (SleighLanguage) currentProgram.getLanguage();
        var library = PcodeUseropLibrary.<byte[]>nil();
        int rawChecks = 0, scheduledChecks = 0;
        for (int index = 0; index < cases.length; index++) {
            monitor.checkCancelled();
            var c = cases[index];var address = toAddr(0x1000L + index * 32L);
            var body = new AddressSet(address, address.add(7));
            if (!new DisassembleCommand(address, body, false).applyTo(currentProgram, monitor)) {
                throw new AssertionError("Cannot disassemble " + address);
            }
            var instruction = getInstructionAt(address);
            if (instruction == null || instruction.getLength() != 2 ||
                !instruction.getMnemonicString().equals(c.mnemonic) ||
                instruction.getScalar(0).getUnsignedValue() != c.immediate ||
                !instruction.getRegister(1).getName().equals(c.destination)) {
                throw new AssertionError("Wrong compact MVK decode at " + address + ": " + instruction);
            }
            for (var op : instruction.getPcode()) if (op.getOpcode() == PcodeOp.CALLOTHER ||
                op.getOpcode() == PcodeOp.UNIMPLEMENTED) throw new AssertionError("Opaque semantics " + instruction);
            Function function = currentProgram.getFunctionManager().createFunction("mvk_" + index,
                address, body, SourceType.USER_DEFINED);
            var result = new C6000PipelineCompiler(currentProgram, function, Set.of()).compile();
            var code = new PcodeProgram(language, Arrays.asList(result.code()), library.getSymbols(language)) {};
            for (var check : c.checks) {
                raw(c, check, address);rawChecks++;
                scheduled(c, check, code);scheduledChecks++;
            }
        }
        if (cases.length != 120 || rawChecks != 360 || scheduledChecks != 360) {
            throw new AssertionError("Incomplete predicate matrix");
        }
        println("C6000_COMPACT_PREDICATED_MVK_OK cases=" + cases.length +
            " raw=" + rawChecks + " scheduled=" + scheduledChecks);
    }
}
