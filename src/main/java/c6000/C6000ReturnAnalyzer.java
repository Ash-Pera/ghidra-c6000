/* ###
 * Copyright 2026 ghidra-c6000 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package c6000;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Classify branches through the C6000 ABI return register before switch analysis. */
public class C6000ReturnAnalyzer extends AbstractAnalyzer {
	public C6000ReturnAnalyzer() {
		super("C6000 Returns", "Classifies B/BNOP through B3 as returns",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		int recovered = 0;
		InstructionIterator instructions = program.getListing().getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			String name = instruction.getMnemonicString();
			if (!(name.endsWith("B.S1") || name.endsWith("B.S2") ||
				name.endsWith("BNOP.S1") || name.endsWith("BNOP.S2"))) continue;
			if (instruction.getFlowOverride() != FlowOverride.NONE ||
				!instruction.getFlowType().isComputed() || instruction.getNumOperands() == 0 ||
				!("B3".equals(instruction.getDefaultOperandRepresentation(0)) ||
					entryLinkCopy(program, instruction))) continue;
			instruction.setFlowOverride(FlowOverride.RETURN);
			recovered++;
		}
		if (recovered > 0) Msg.info(this, getName() + "> recovered " + recovered + " return(s)");
		return true;
	}

	/**
	 * A branch through a register whose only writer in the function is an
	 * unpredicated copy of B3 made before any branch or B3 write on the
	 * entry's straight-line path: it returns through the caller's link.
	 */
	static boolean entryLinkCopy(Program program, Instruction branch) {
		Register target = branch.getRegister(0), b3 = program.getRegister("B3");
		Function function = program.getFunctionManager().getFunctionContaining(branch.getAddress());
		if (target == null || function == null ||
			!target.getName().startsWith("B") || target.equals(b3)) return false;
		Instruction copy = null;
		for (Instruction i : program.getListing().getInstructions(function.getBody(), true)) {
			if (i.getDelaySlotDepth() != 0) continue;
			for (Object o : i.getResultObjects()) {
				if (!(o instanceof Register r) || !(r.contains(target) || target.contains(r))) continue;
				if (copy != null) return false;
				copy = i;
			}
		}
		if (copy == null || !b3.equals(C6000EncodingInfo.registerCopySource(copy))) return false;
		var references = program.getReferenceManager();
		for (Instruction i = program.getListing().getInstructionAt(function.getEntryPoint()); i != null;
				i = program.getListing().getInstructionAt(i.getMaxAddress().next())) {
			if (i.equals(copy)) return true;
			if (!i.getAddress().equals(function.getEntryPoint()) &&
				references.getReferenceCountTo(i.getAddress()) != 0) return false;
			if (i.getDelaySlotDepth() != 0 || i.getFlowType().isJump() || i.getFlowType().isCall() ||
				i.getFlowType().isTerminal() || !i.getFlowType().hasFallthrough()) return false;
			for (Object o : i.getResultObjects()) {
				if (o instanceof Register r && (r.contains(b3) || b3.contains(r))) return false;
			}
		}
		return false;
	}
}
