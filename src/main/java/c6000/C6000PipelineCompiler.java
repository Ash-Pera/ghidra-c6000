// SPDX-License-Identifier: Apache-2.0
package c6000;
import java.math.BigInteger;
import java.util.*;
import java.util.regex.*;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.pcode.*;
/**
* Exact finite-state retiming of raw instruction p-code. Arithmetic is never
* reimplemented here. SPRUFE8B 3.5, 3.8.3, 3.10.2.2 and 4.2.1--4.2.8:
* E1 scalar capture, DP ports through E4, memory at E3, split delayed
* writeback through E10, software-loop dispatch, and branch landing C+6.
* Unsupported phase contracts fail before enabling this representation.
* A drained entry pipeline is an explicit precondition, never inferred from
* a function boundary. Use C6000PipelineSchedules.enable to record its evidence.
*/
public final class C6000PipelineCompiler {

    public record Result(PcodeOp[] code,int states,int packets,AddressSet covered,Map<Integer,Long> cycleStarts,Map<Integer,Integer> stallTargets){
    }

    private record Flight(long pc,int age){
    }

    private record Branch(long pc,int age,long target,boolean returns){
    }

    private record Hazard(long pc,List<Long> registers){
    }

    private record LoopFrame(long start,int time,int drain,boolean zero,boolean refill,boolean abrupt) {}
    private record LoopCell(List<Insn> source,List<Insn> buffered,int mask,long nextPc) {}
    private record LoopPlan(long start,String kind,int ii,int fetchDelay,int cap,List<LoopCell> cells,long postPc) {}
    private record State(long pc,int idle,List<Flight> flights,List<Branch> branches,List<Hazard> hazards,LoopFrame loop){
    }

    private record Dest(long offset,int size,boolean flags,int phase,long valueOffset,long mask){
    }

    private record Read(long offset,int first,int last,int phases) {}

    private record Insn(Instruction instruction,String name,PcodeOp[] raw,List<Long> regs,List<Dest> outputs,int latency,int ready,List<Read> reads,int guard,int span,boolean load,boolean store,Register predicate,boolean inverted){
    }

    private record Eval(long image,Varnode predicate,Map<Long,Varnode> flags){
    }
    private final Program program;
    private final Function function;
    private final Address entry;
    private final List<Long> entryWrites;
    private final AddressSpace unique,constant;
    private final Builder b;
    private final Map<Long,Insn> instructions=new HashMap<>();
    private final Map<Long,LoopPlan> loopPlans=new HashMap<>();
    private final LinkedHashMap<State,Integer> states=new LinkedHashMap<>();
    private final Map<String,Varnode> slots=new HashMap<>();
    private final AddressSet covered=new AddressSet();

    private long nextUnique=0x10000000;

    private int packets;
    private final Map<Integer,Long> cycleStarts=new LinkedHashMap<>();
    private final Map<Integer,String> stallLabels=new LinkedHashMap<>();
    private static final Set<String> SINGLE=Set.of("ADD","ADDK","ADDAW","ADDAD","ADDAH","ADDAB","SUBAW","SUBAH","SUBAB","SUB","AND","OR","XOR","NOT","MV","MVK","MVKH","MVKL","MVKLH","SHL","SHR","SHRU","EXT","EXTU","SET","CLR","CMPEQ","CMPGT","CMPLT","CMPEQSP","CMPGTSP","CMPLTSP","CMPGTU","CMPLTU","ZERO","NEG","ABS","NORM","LMBD","ABSSP","DINT","RINT");

    public C6000PipelineCompiler(Program p,Function f){
        this(p,f,Set.of());
    }

    public C6000PipelineCompiler(Program p,Function f,Set<String> previousE1Writes){
        program=p;
        function=f;
        entry=f.getEntryPoint();
        unique=p.getAddressFactory().getUniqueSpace();
        constant=p.getAddressFactory().getConstantSpace();
        b=new Builder();
        TreeSet<Long> writes=new TreeSet<>();
        for(String name:previousE1Writes){
            if(!name.matches("[AB]([0-9]|[12][0-9]|3[01])"))throw fail("entry hazard must name a 32-bit GPR: "+name);
            writes.add(p.getRegister(name).getAddress().getOffset());
        }
        entryWrites=List.copyOf(writes);
    }

    private Varnode temp(int size){
        long at=nextUnique;
        nextUnique+=(size+15)&~15;
        return new Varnode(unique.getAddress(at),size);
    }

    private long image(){
        long at=nextUnique;
        nextUnique+=0x4000;
        return at;
    }

    private Varnode im(long base,long off,int size){
        return new Varnode(unique.getAddress(base+off),size);
    }

    private Varnode c(long value,int size){
        return new Varnode(constant.getAddress(value),size);
    }

    private Varnode arch(long off,int size){
        return new Varnode(program.getAddressFactory().getRegisterSpace().getAddress(off),size);
    }

    private Varnode slot(String kind,long pc,int age,long off,int size){
        return slots.computeIfAbsent(kind+":"+pc+":"+age+":"+off+":"+size,k->temp(size));
    }

    private int state(State s){
        Integer n=states.get(s);
        if(n!=null)return n;
        if(states.size()>=4096)throw fail("schedule exceeds 4096 distinct pipeline states");
        int i=states.size();
        states.put(s,i);
        return i;
    }

    private IllegalArgumentException fail(String message){
        return new IllegalArgumentException("C6000 schedule "+entry+": "+message);
    }

    private static String base(Instruction i){
        String n=i.getMnemonicString().trim();
        int j=n.indexOf(']');
        if(n.startsWith("[")&&j>=0)n=n.substring(j+1).trim();
        if(n.startsWith("_"))n=n.substring(1).trim();
        int dot=n.indexOf('.');
        return dot<0?n:n.substring(0,dot);
    }

    private Insn decode(long pc)throws Exception{
        if(instructions.containsKey(pc))return instructions.get(pc);
        Address at=entry.getNewAddress(pc);
        var owner=program.getFunctionManager().getFunctionContaining(at);
        if(program.getListing().getDefinedDataContaining(at)!=null)throw fail("scheduled code conflicts with defined data at "+at);
        if(owner!=null&&!owner.equals(function))throw fail("flow enters another function at "+at);
        if(pc>function.getBody().getMaxAddress().getOffset()+254||pc<function.getBody().getMinAddress().getOffset())throw fail("flow leaves owned code at "+at);
        var context=new ProcessorContextImpl(program.getLanguage());
        var value=program.getProgramContext().getRegisterValue(program.getLanguage().getContextBaseRegister(),at);
        if(value!=null)context.setRegisterValue(value);
        context.setRegisterValue(new RegisterValue(program.getRegister("c_flow_delay"),BigInteger.ZERO));
        context.setRegisterValue(new RegisterValue(program.getRegister("c_schedule_entry"),BigInteger.ZERO));
        context.setRegisterValue(new RegisterValue(program.getRegister("c_branch_terminal"),BigInteger.ONE));
        var memory=new DumbMemBufferImpl(program.getMemory(),at);
        var prototype=program.getLanguage().parse(memory,context,false);
        var ins=new PseudoInstruction(program,at,prototype,memory,context);
        String name=base(ins);
        boolean load=name.startsWith("LD"),store=name.startsWith("ST");
        int latency;
        if(name.equals("CPKT"))latency=0;
        else if(load)latency=5;
        else if(store)latency=3;
        else if(Set.of("ADDSP","SUBSP","MPYSP","MVD","DPSP","DPINT","DPTRUNC","INTSP","SPINT","SPTRUNC").contains(name))latency=4;
        else if(Set.of("MPY","MPYSU","MPYU","MPYUS","SPDP","ABSDP","RCPDP","RSQRDP","CMPEQDP","CMPLTDP","CMPGTDP").contains(name))latency=2;
        else if(Set.of("ADDDP","SUBDP","MPYSPDP").contains(name))latency=7;
        else if(Set.of("INTDP","INTDPU","MPYSP2DP").contains(name))latency=5;
        else if(name.equals("MPYDP"))latency=10;
        else if(name.equals("MVC")){
            latency=1;
            Set<String> ordinary=Set.of("AMR","CSR","FADCR","FAUCR","FMCR","ILC","RILC","TSR");
            for(int operand=0;operand<ins.getNumOperands();operand++) {
                for(Object object:ins.getOpObjects(operand)) if(object instanceof Register register) {
                    String registerName=register.getName();
                    if(!registerName.matches("[AB]([0-9]|[12][0-9]|3[01])")&&!ordinary.contains(registerName))                         throw fail("unimplemented control-register phase contract at "+at+": "+registerName);
                }
            }
        }
        else if(SINGLE.contains(name)||Set.of("NOP","B","BNOP","ADDKPC","SPLOOP","SPLOOPD","SPLOOPW","SPMASK","SPKERNEL").contains(name))latency=1;
        else throw fail("unimplemented phase contract "+ins+" at "+at);
        // An updating load with an aliased destination needs a separate write-priority
        // contract (SPRUFE8B 3.7). Never guess which of the two writes wins.
        if(load&&(ins.toString().contains("++")||ins.toString().contains("--"))){
            Register destination=ins.getRegister(ins.getNumOperands()-1);
            if(destination==null)throw fail("load destination missing at "+at);
            for(Object operand:ins.getOpObjects(0))if(operand instanceof Register source){
                long lo=source.getAddress().getOffset(),hi=lo+source.getMinimumByteSize();
                long dlo=destination.getAddress().getOffset(),dhi=dlo+destination.getMinimumByteSize();
                if(lo<dhi&&hi>dlo)throw fail("updating load aliases its destination at "+at);
            }
        }
        var raw=Set.of("SPLOOP","SPLOOPD","SPLOOPW","SPMASK","SPKERNEL").contains(name)?new PcodeOp[0]:ins.getPcode(false);
        TreeSet<Long> regs=new TreeSet<>();
        Map<String,Dest> destinations=new LinkedHashMap<>();
        for(var op:raw){
            if(op.getOpcode()==PcodeOp.UNIMPLEMENTED||op.getOpcode()==PcodeOp.CALLOTHER)throw fail("opaque semantics at "+at);
            List<Varnode> nodes=new ArrayList<>(Arrays.asList(op.getInputs()));
            if(op.getOutput()!=null)nodes.add(op.getOutput());
            for(var v:nodes)if(v.isRegister()){
                long off=v.getOffset()&~3L;
                for(long k=off;k<v.getOffset()+v.getSize();k+=4)regs.add(k);
            }
            var out=op.getOutput();
            if(out!=null&&out.isRegister()){
                var reg=program.getRegister(out.getAddress(),out.getSize());
                if(reg==null)throw fail("unknown architectural output at "+at);
                boolean flags=(Set.of("FADCR","FAUCR","FMCR").contains(reg.getName())&&!name.equals("MVC")) || (name.equals("ABS")&&Set.of("CSR","SSR").contains(reg.getName()));
                destinations.put(out.getOffset()+":"+out.getSize(),new Dest(out.getOffset(),out.getSize(),flags,latency,out.getOffset(),-1));
            }
        }
        // SPRUFE8B 4.2.7--4.2.16: semantic read words and independent write phases.
        List<Read> reads=new ArrayList<>();int ready=1;
        if(Set.of("ADDDP","SUBDP","CMPEQDP","CMPLTDP","CMPGTDP","MPYSPDP").contains(name)){
            ready=2;
            if(name.endsWith("DP")&&name.startsWith("CMP"))addRead(reads,ins.getRegister(0),true,2,2);
            // The reversed .S SUBDP spelling swaps displayed operands, not the
            // encoded source ports (SPRUFE8B SUBDP opcode maps; 4.2.8).
            boolean reversed=name.equals("SUBDP")&&ins.getMnemonicString().contains(".S")&&(program.getMemory().getInt(at)&0x80)!=0;
            addRead(reads,ins.getRegister(reversed?0:1),true,2,2);
            if(name.equals("MPYSPDP"))addRead(reads,ins.getRegister(0),false,1,2);
        }
        if(name.equals("MPYDP")){
            ready=4;
            addRead(reads,ins.getRegister(0),false,1,2);addRead(reads,ins.getRegister(0),true,3,4);
            addRead(reads,ins.getRegister(1),false,1,3);addRead(reads,ins.getRegister(1),true,2,4);
        }
        Map<String,Dest> phased=new LinkedHashMap<>();
        for(var d:destinations.values()){
            int phase=d.phase();
            if(load||store)phase=(load&&isLoadData(ins,d))?5:1;
            if(Set.of("SPDP","ABSDP","RCPDP","RSQRDP").contains(name))phase=1;
            if(Set.of("ADDDP","SUBDP","MPYSPDP").contains(name))phase=6;
            if(Set.of("INTDP","INTDPU","MPYSP2DP").contains(name))phase=4;
            if(name.equals("MPYDP"))phase=9;
            if(d.size()==8&&Set.of("SPDP","ABSDP","RCPDP","RSQRDP","ADDDP","SUBDP","MPYSPDP","INTDP","INTDPU","MPYSP2DP","MPYDP").contains(name)){
                long low=d.offset()+(program.getLanguage().isBigEndian()?4:0),high=d.offset()+(program.getLanguage().isBigEndian()?0:4);
                phased.put(low+":4",new Dest(low,4,false,phase,low,-1));phased.put(high+":4",new Dest(high,4,false,phase+1,high,-1));
            }else phased.put(d.offset()+":"+d.size(),new Dest(d.offset(),d.size(),d.flags(),phase,d.valueOffset(),d.mask()));
        }
        // MVC's explicitly named register changes in E1 (2.8.2), but the loop
        // counter interface observes ILC/RILC loads four cycles later (7.4.3--4).
        if(name.equals("MVC"))for(String counter:List.of("ILC","RILC")){
            long offset=program.getRegister(counter).getAddress().getOffset();
            if(phased.containsKey(offset+":4")){
                long target=program.getRegister("C6000_PIPE_"+counter).getAddress().getOffset();
                phased.put(target+":4",new Dest(target,4,false,4,offset,-1));latency=4;
            }
        }
        if(name.equals("DINT")||name.equals("RINT"))for(String control:List.of("CSR","TSR")){
            long offset=program.getRegister(control).getAddress().getOffset();var d=phased.get(offset+":4");if(d==null)throw fail("missing interrupt-control output");
            phased.put(offset+":4",new Dest(offset,4,false,1,offset,control.equals("CSR")?1:3));
        }
        destinations=phased;
        int span=1;
        if(name.equals("NOP"))span=Math.max(1,(int)ins.getScalar(0).getValue());
        if(name.equals("BNOP"))span=1+(int)ins.getScalar(1).getValue();
        if(name.equals("ADDKPC"))span=1+(int)ins.getScalar(2).getValue();
        if(load&&C6000ExecutionPackets.protectedLoad(program,ins))span=5;
        Register pred=null;
        boolean inverted=false;
        Matcher pm=Pattern.compile("\\[(!?)([AB][012])\\]").matcher(ins.getMnemonicString());
        if(pm.find()){
            pred=program.getRegister(pm.group(2));
            inverted=!pm.group(1).isEmpty();
            regs.add(pred.getAddress().getOffset());
        }
        int guard=-1;
        if(pred!=null&&ready>1){
            // Recognize the dominating instruction predicate guard, not an arithmetic branch.
            for(int n=0;n<raw.length;n++){
                var op=raw[n];
                if(op.getOutput()!=null&&op.getOutput().isRegister())break;
                boolean otherRegister=Arrays.stream(op.getInputs()).anyMatch(v->v.isRegister()&&v.getOffset()!=predOffset(ins));
                if(otherRegister)break;
                if(op.getOpcode()==PcodeOp.CBRANCH){
                    if(op.getInput(0).isConstant()&&n+(int)op.getInput(0).getOffset()==raw.length)guard=n;
                    break;
                }
            }
            if(guard<0)throw fail("cannot prove delayed predicate guard at "+at);
        }
        var desc=new Insn(ins,name,raw,List.copyOf(regs),List.copyOf(destinations.values()),latency,ready,List.copyOf(reads),guard,span,load,store,pred,inverted);
        instructions.put(pc,desc);
        return desc;
    }

    private long predOffset(Instruction instruction){
        Matcher predicate=Pattern.compile("\\[!?([AB][012])\\]").matcher(instruction.getMnemonicString());
        if(!predicate.find())throw fail("predicate disappeared");
        return program.getRegister(predicate.group(1)).getAddress().getOffset();
    }

    private void addRead(List<Read> reads,Register register,boolean high,int first,int last){
        if(register==null)throw fail("missing DP source register");
        long offset=register.getAddress().getOffset();
        if(high){if(register.getMinimumByteSize()!=8)throw fail("DP source is not a pair");offset+=program.getLanguage().isBigEndian()?0:4;}
        else if(register.getMinimumByteSize()==8)offset+=program.getLanguage().isBigEndian()?4:0;
        int phases=((1<<last)-1)^((1<<(first-1))-1);
        if(first==1&&last==3)phases=5;if(first==2&&last==4)phases=10;
        reads.add(new Read(offset,first,last,phases));
    }

    private boolean isLoadData(Instruction ins,Dest d){
        var r=ins.getRegister(ins.getNumOperands()-1);
        if(r==null)throw fail("load destination missing at "+ins.getAddress());
        return d.offset()<r.getAddress().getOffset()+r.getMinimumByteSize()&&d.offset()+d.size()>r.getAddress().getOffset();
    }

    private long after(Insn i)throws Exception{
        long pc=i.instruction().getMaxAddress().getOffset()+1;
        Address at=entry.getNewAddress(pc);
        if((pc&31)==28&&program.getMemory().contains(at.add(3))&&(program.getMemory().getInt(at)>>>28)==0xe){
            covered.add(at,at.add(3));
            pc+=4;
        }
        return pc;
    }

    private List<Insn> packet(long pc)throws Exception{
        List<Insn> result=new ArrayList<>();
        Insn i=decode(pc);
        while(i.name().equals("CPKT"))i=decode(after(i));
        while(true){
            result.add(i);
            covered.add(i.instruction().getMinAddress(),i.instruction().getMaxAddress());
            if(result.size()>8)throw fail("oversized execute packet");
            if(!C6000ExecutionPackets.parallelWithNext(program,i.instruction()))break;
            i=decode(after(i));
        }
        return result;
    }

    private boolean dataDest(Insn i,Dest d){
        if(!i.load())return !i.store();
        var r=i.instruction().getRegister(i.instruction().getNumOperands()-1);
        if(r==null)throw fail("load destination missing at "+i.instruction().getAddress());
        return d.offset()<r.getAddress().getOffset()+r.getMinimumByteSize()&&d.offset()+d.size()>r.getAddress().getOffset();
    }

    private Eval evaluate(Insn i,Integer age,boolean actualMemory,Map<Long,Varnode> late)throws Exception{
        long pc=i.instruction().getAddress().getOffset(),img=image();
        for(long off:i.regs())b.op(PcodeOp.COPY,im(img,off,4),late.containsKey(off)?late.get(off):age==null?arch(off,4):slot("input",pc,age,off,4));
        Varnode predicate=age==null?temp(1):slot("predicate",pc,age,0,1);
        if(age==null){
            if(i.predicate()==null)b.op(PcodeOp.COPY,predicate,c(1,1));
            else b.op(i.inverted()?PcodeOp.INT_EQUAL:PcodeOp.INT_NOTEQUAL,predicate,arch(i.predicate().getAddress().getOffset(),4),c(0,4));
        }
        Map<Long,Varnode> flags=new LinkedHashMap<>();
        for(var d:i.outputs())if(d.flags()){
            var flag=temp(d.size());
            flags.put(d.offset(),flag);
            b.op(PcodeOp.COPY,flag,c(0,d.size()));
        }
        String prefix="raw"+b.labelCounter++ +"_";
        PcodeOp[] raw=i.raw();
        // Relocate connected unique-space byte intervals, preserving overlapping
        // subpieces. Raw unique offsets are not register-image offsets.
        TreeSet<Long> bytes=new TreeSet<>();
        for(var op:raw){
            List<Varnode> all=new ArrayList<>(Arrays.asList(op.getInputs()));
            if(op.getOutput()!=null)all.add(op.getOutput());
            for(var v:all)if(v.isUnique())for(long k=v.getOffset();k<v.getOffset()+v.getSize();k++)bytes.add(k);
        }
        TreeMap<Long,Long> translations=new TreeMap<>();
        Long first=null,last=null;
        for(long at:bytes){
            if(first==null)first=at;
            else if(at!=last+1){
                translations.put(first,temp((int)(last-first+1)).getOffset());
                first=at;
            }
            last=at;
        }
        if(first!=null)translations.put(first,temp((int)(last-first+1)).getOffset());
        java.util.function.Function<Varnode,Varnode> mapper=v->{
            if(v.isRegister())return im(img,v.getOffset(),v.getSize());
            if(v.isUnique()){
                var tr=translations.floorEntry(v.getOffset());
                return new Varnode(unique.getAddress(tr.getValue()+v.getOffset()-tr.getKey()),v.getSize());
            }
            return v;
        };
        for(int n=0;n<raw.length;n++){
            b.label(prefix+n);
            var op=raw[n];
            int opcode=op.getOpcode();
            if(n==i.guard()){
                b.jump(PcodeOp.CBRANCH,prefix+raw.length,not(predicate));continue;
            }
            if(opcode==PcodeOp.LOAD&&!actualMemory){
                b.op(PcodeOp.COPY,mapper.apply(op.getOutput()),c(0,op.getOutput().getSize()));
                continue;
            }
            if(opcode==PcodeOp.STORE&&!actualMemory)continue;
            if(opcode==PcodeOp.BRANCHIND||opcode==PcodeOp.RETURN||opcode==PcodeOp.CALL||opcode==PcodeOp.CALLIND)continue;
            Varnode[] inputs=Arrays.stream(op.getInputs()).map(mapper).toArray(Varnode[]::new);
            Varnode output=op.getOutput()==null?null:mapper.apply(op.getOutput());
            if(opcode==PcodeOp.BRANCH||opcode==PcodeOp.CBRANCH){
                var target=op.getInput(0);
                if(target.isConstant())b.jump(opcode,prefix+(n+(int)target.getOffset()),opcode==PcodeOp.CBRANCH?inputs[1]:null);
                else if(opcode==PcodeOp.CBRANCH)b.jump(opcode,prefix+raw.length,inputs[1]);
                else b.jump(PcodeOp.BRANCH,prefix+raw.length,null);
                continue;
            }
            var out=op.getOutput();
            if(out!=null&&out.isRegister()&&flags.containsKey(out.getOffset())){
                // Keep the event bits, including already-set bits. Merging a
                // computed old|flags value at E4 would undo an intervening MVC.
                if(opcode!=PcodeOp.INT_OR)throw fail("unsupported sticky status update at "+i.instruction().getAddress());
                int other=op.getInput(0).isRegister()&&op.getInput(0).getOffset()==out.getOffset()?1:op.getInput(1).isRegister()&&op.getInput(1).getOffset()==out.getOffset()?0:-1;
                if(other<0)throw fail("sticky status update does not expose event flags");
                b.op(PcodeOp.INT_OR,flags.get(out.getOffset()),flags.get(out.getOffset()),inputs[other]);
            }
            b.op(opcode,output,inputs);
        }
        b.label(prefix+raw.length);
        return new Eval(img,predicate,flags);
    }

    private void commit(Insn i,Eval eval,int phase)throws Exception{
        String end="commit"+b.labelCounter++;
        b.jump(PcodeOp.CBRANCH,end,not(eval.predicate()));
        for(var d:i.outputs())if(d.phase()==phase){
            Varnode value=d.flags()?eval.flags().get(d.offset()):im(eval.image(),d.valueOffset(),d.size());
            if (d.flags()) b.op(PcodeOp.INT_OR, arch(d.offset(),d.size()), arch(d.offset(),d.size()), value);
            else if(d.mask()==-1)b.op(PcodeOp.COPY, arch(d.offset(),d.size()), value);
            else{var keep=temp(d.size());var bits=temp(d.size());b.op(PcodeOp.INT_AND,keep,arch(d.offset(),d.size()),c(~d.mask(),d.size()));b.op(PcodeOp.INT_AND,bits,value,c(d.mask(),d.size()));b.op(PcodeOp.INT_OR,arch(d.offset(),d.size()),keep,bits);}
        }
        b.label(end);
    }

    private Varnode not(Varnode v){
        var result=temp(1);
        b.op(PcodeOp.BOOL_NEGATE,result,v);
        return result;
    }

    private List<Long> e1Outputs(Insn i){
        List<Long> r=new ArrayList<>();
        for(var d:i.outputs())if(!d.flags()&&d.phase()==1)for(long off=d.offset()&~3L;off<d.offset()+d.size();off+=4)if(off<0x2000)r.add(off);
        return List.copyOf(r);
    }

    private Set<Long> crossReads(List<Insn> packet){
        Set<Long> r=new HashSet<>();
        for(var i:packet){
            if(i.load()||i.store())continue;
            String mn=i.instruction().getMnemonicString();
            int side=mn.matches(".*\\.[LSDM]1.*")?0:mn.matches(".*\\.[LSDM]2.*")?1:-1;
            if(side<0)continue;
            int count=i.instruction().getNumOperands()-(i.name().equals("B")||i.name().equals("BNOP")?0:1);
            for(int k=0;k<count;k++)for(Object obj:i.instruction().getOpObjects(k))if(obj instanceof Register reg){
                long off=reg.getAddress().getOffset();
                if(off<0x2000&&((off>=0x1000)?1:0)!=side)for(long x=off;x<off+reg.getMinimumByteSize();x+=4)r.add(x);
            }
        }
        return r;
    }

    public Result compile()throws Exception{
        for(String counter:List.of("ILC","RILC"))b.op(PcodeOp.COPY,new Varnode(program.getRegister("C6000_PIPE_"+counter).getAddress(),4),new Varnode(program.getRegister(counter).getAddress(),4));
        List<Hazard> incoming=List.of();
        if(!entryWrites.isEmpty()){
            // The preceding E1 packet is outside this function. Its writes are already
            // visible, but an X-path reader can still incur one pipeline-wide stall.
            incoming=List.of(new Hazard(-1,entryWrites));
            b.op(PcodeOp.COPY,slot("hazard",-1,0,0,1),c(1,1));
        }
        State start=new State(entry.getOffset(),0,List.of(),List.of(),incoming,null);
        state(start);
        int processed=0;
        while(processed<states.size()){
            var iterator=states.entrySet().iterator();
            Map.Entry<State,Integer> selected=null;
            for(int k=0;k<=processed;k++)selected=iterator.next();
            State s=selected.getKey();
            int id=selected.getValue();
            b.label("node"+id);
            processed++;
            LoopPlan loop=s.loop()==null?null:loopPlans.get(s.loop().start());
            boolean sourceFetch=loop!=null&&s.loop().time()<loop.cells().size();
            boolean fetch=loop==null||sourceFetch||postFetch(loop,s.loop());
            List<Insn> fetched=!fetch||s.idle()>0?List.of():sourceFetch?loop.cells().get(s.loop().time()).source():packet(s.pc());
            long fetchNext=fetched.isEmpty()?s.pc():sourceFetch?loop.cells().get(s.loop().time()).nextPc():after(fetched.get(fetched.size()-1));
            List<Insn> pack=loop==null?fetched:loopOperations(loop,s.loop(),fetched);
            Insn loopStart=null;
            for(var instruction:fetched)if(instruction.name().equals("SPLOOP")||instruction.name().equals("SPLOOPD")||instruction.name().equals("SPLOOPW")){
                if(loop!=null||loopStart!=null)throw fail("overlapping loop invocation requires a reload contract");
                if(instruction.predicate()!=null&&!instruction.name().equals("SPLOOPW"))throw fail("predicated loop start requires reload state");
                loopStart=instruction;planLoop(instruction);
            }
            Varnode whileSample=null;
            if(loop!=null&&loop.kind().equals("SPLOOPW")&&!s.loop().abrupt()){
                var instruction=decode(loop.start());whileSample=temp(1);b.op(instruction.inverted()?PcodeOp.INT_EQUAL:PcodeOp.INT_NOTEQUAL,whileSample,arch(instruction.predicate().getAddress().getOffset(),4),c(0,4));
            }
            Varnode counterBefore=temp(4);b.op(PcodeOp.COPY,counterBefore,ilc());
            Varnode ilcBefore=null;if(loopStart!=null&&loopStart.name().equals("SPLOOP")){ilcBefore=temp(4);b.op(PcodeOp.COPY,ilcBefore,ilc());}
            int fetchSpan=1;for(var instruction:fetched)fetchSpan=Math.max(fetchSpan,instruction.span());
            if(sourceFetch)fetchSpan=1;
            try{validateUnits(pack);}catch(IllegalArgumentException error){throw fail(error.getMessage()+" frame="+s.loop()+" pc="+Long.toHexString(s.pc()));}
            for(var flight:s.flights()){
                var old=decode(flight.pc());int latency=Set.of("ADDDP","SUBDP","CMPEQDP","CMPLTDP","CMPGTDP","MPYSP2DP").contains(old.name())?2:old.name().equals("MPYDP")?4:old.name().equals("MPYSPDP")?3:1;
                if(flight.age()<latency)for(var instruction:pack)if(unit(old)!=0&&unit(old)==unit(instruction))throw fail("functional unit still occupied by "+old.instruction());
            }
            if(!pack.isEmpty())packets++;
            Set<Long> crosses=new HashSet<>();
            for(var instruction:pack){Set<Long> ports=crossReads(List.of(instruction));for(var read:instruction.reads())if(read.first()>1)ports.remove(read.offset());crosses.addAll(ports);}
            for(var flight:s.flights()){
                var instruction=decode(flight.pc());Set<Long> ports=crossReads(List.of(instruction));
                for(var read:instruction.reads())if((read.phases()&(1<<flight.age()))!=0&&ports.contains(read.offset()))crosses.add(read.offset());
            }
            Varnode stall=null;
            for(var h:s.hazards())if(h.registers().stream().anyMatch(crosses::contains)){
                var v=slot("hazard",h.pc(),0,0,1);
                if(stall==null)stall=v;
                else{
                    var sum=temp(1);
                    b.op(PcodeOp.BOOL_OR,sum,stall,v);
                    stall=sum;
                }
            }
            if(stall!=null){
                String target="node"+state(new State(s.pc(),s.idle(),s.flights(),s.branches(),List.of(),s.loop()));
                stallLabels.put(b.code.size(),target);
                b.jump(PcodeOp.CBRANCH,target,stall);
            }
            cycleStarts.put(b.code.size(),s.pc());
            b.op(PcodeOp.COPY,temp(1),c(0,1));
            // removable trace anchor, no architectural effect
            Map<Long,Eval> issued=new LinkedHashMap<>();
            Map<Long,Map<Long,Varnode>> captured=new LinkedHashMap<>();
            Insn issueBranch=null;
            int span=1;
            for(var i:pack){
                long pc=i.instruction().getAddress().getOffset();
                Map<Long,Varnode> input=new LinkedHashMap<>();
                for(long off:i.regs()){
                    var value=temp(4);
                    b.op(PcodeOp.COPY,value,arch(off,4));
                    input.put(off,value);
                }
                captured.put(pc,input);
                Eval e;
                if(i.ready()==1)e=evaluate(i,null,false,Map.of());
                else{var pred=temp(1);if(i.predicate()==null)b.op(PcodeOp.COPY,pred,c(1,1));else b.op(i.inverted()?PcodeOp.INT_EQUAL:PcodeOp.INT_NOTEQUAL,pred,arch(i.predicate().getAddress().getOffset(),4),c(0,4));e=new Eval(0,pred,Map.of());}
                issued.put(pc,e);
                span=Math.max(span,i.span());
                if(i.name().equals("B")||i.name().equals("BNOP")){
                    if(issueBranch!=null)throw fail("multiple branches in a packet");
                    issueBranch=i;
                }
            }
            // Capture late ports before any writeback in this cycle. A repeated port
            // read requires a stable word across its documented read window; reject
            // a potential intervening writer rather than choosing an arbitrary sample.
            Map<Flight,Map<Long,Varnode>> lateInputs=new LinkedHashMap<>();
            for(var f:s.flights()){
                var i=decode(f.pc());Map<Long,Varnode> late=new LinkedHashMap<>();
                for(var read:i.reads())if(read.first()==f.age()+1){var value=temp(4);b.op(PcodeOp.COPY,value,arch(read.offset(),4));late.put(read.offset(),value);}
                lateInputs.put(f,late);
            }
            List<Dest> writesThisCycle=new ArrayList<>();
            for(var i:pack)for(var d:i.outputs())if(d.phase()==1)writesThisCycle.add(d);
            for(var f:s.flights())for(var d:decode(f.pc()).outputs())if(d.phase()==f.age()+1)writesThisCycle.add(d);
            for(var i:pack)checkStable(i,1,writesThisCycle);
            for(var f:s.flights())checkStable(decode(f.pc()),f.age()+1,writesThisCycle);
            Map<Flight,Eval> mature=new LinkedHashMap<>();
            for(var f:s.flights()){
                var i=decode(f.pc());if(i.load()&&f.age()==2||!i.load()&&!i.store()&&i.ready()>1&&f.age()==i.ready()-1)
                    mature.put(f,evaluate(i,f.age(),true,lateInputs.get(f)));
            }
            for(var f:s.flights())if(f.age()==2&&decode(f.pc()).store())mature.put(f,evaluate(decode(f.pc()),f.age(),true,lateInputs.get(f)));
            for(var f:s.flights()){
                var i=decode(f.pc());int phase=f.age()+1;
                if(i.outputs().stream().noneMatch(d->d.phase()==phase))continue;
                var e=mature.get(f);
                if(e==null){Map<Long,Varnode> flags=new LinkedHashMap<>();long img=image();for(var d:i.outputs())if(d.phase()==phase){var value=slot("output",f.pc(),f.age(),d.offset(),d.size());if(d.flags())flags.put(d.offset(),value);else b.op(PcodeOp.COPY,im(img,d.valueOffset(),d.size()),value);}e=new Eval(img,slot("predicate",f.pc(),f.age(),0,1),flags);}
                commit(i,e,phase);
            }
            for(var i:pack)if(i.outputs().stream().anyMatch(d->d.phase()==1))commit(i,issued.get(i.instruction().getAddress().getOffset()),1);
            List<Flight> nextFlights=new ArrayList<>();
            List<Runnable> moves=new ArrayList<>();
            for(var f:s.flights()){
                var i=decode(f.pc());
                if(f.age()>=i.latency()-1)continue;
                int age=f.age()+1;
                nextFlights.add(new Flight(f.pc(),age));
                copy(moves,slot("predicate",f.pc(),age,0,1),slot("predicate",f.pc(),f.age(),0,1));
                for(long off:i.regs())copy(moves,slot("input",f.pc(),age,off,4),lateInputs.get(f).getOrDefault(off,slot("input",f.pc(),f.age(),off,4)));
                for(var d:i.outputs())if(d.phase()>age&&!i.store()&&f.age()>=(i.load()?3:i.ready())-1){
                    var e=mature.get(f);
                    Varnode from=e==null?slot("output",f.pc(),f.age(),d.offset(),d.size()):d.flags()?e.flags().get(d.offset()):im(e.image(),d.valueOffset(),d.size());
                    copy(moves,slot("output",f.pc(),age,d.offset(),d.size()),from);
                }
            }
            List<Hazard> hazards=new ArrayList<>();
            for(var i:pack){
                long pc=i.instruction().getAddress().getOffset();
                var e=issued.get(pc);
                var writes=e1Outputs(i);
                if(!writes.isEmpty()){
                    hazards.add(new Hazard(pc,writes));
                    copy(moves,slot("hazard",pc,0,0,1),e.predicate());
                }
                if(i.latency()>1){
                    nextFlights.add(new Flight(pc,1));
                    copy(moves,slot("predicate",pc,1,0,1),e.predicate());
                    for(var v:captured.get(pc).entrySet())copy(moves,slot("input",pc,1,v.getKey(),4),v.getValue());
                    if(!i.load()&&!i.store()&&i.ready()==1)for(var d:i.outputs())if(d.phase()>1)copy(moves,slot("output",pc,1,d.offset(),d.size()),d.flags()?e.flags().get(d.offset()):im(e.image(),d.valueOffset(),d.size()));
                }
            }
            long nextPc=fetchNext;
            int idle=s.idle()>0?s.idle()-1:fetchSpan-1;
            Branch landing=null;
            List<Branch> nextBranches=new ArrayList<>();
            for(var branch:s.branches()){
                if(branch.age()==5){
                    if(landing!=null)throw fail("simultaneous branch landings");
                    landing=branch;
                }
                else{
                    nextBranches.add(new Branch(branch.pc(),branch.age()+1,branch.target(),branch.returns()));
                    if(branch.returns())copy(moves,slot("target",branch.pc(),branch.age()+1,0,4),slot("target",branch.pc(),branch.age(),0,4));
                }
            }
            for(var move:moves)move.run();
            if(landing!=null){
                idle=0;
                if(landing.returns()){
                    if(!nextFlights.isEmpty()||!nextBranches.isEmpty()||issueBranch!=null)throw fail("return leaves architectural pipeline effects pending");
                    b.op(PcodeOp.COPY,new Varnode(program.getRegister("C6000_PIPE_RET").getAddress(),4),slot("target",landing.pc(),landing.age(),0,4));
                    if(loop!=null){var tsr=program.getRegister("TSR");b.op(PcodeOp.INT_AND,new Varnode(tsr.getAddress(),4),new Varnode(tsr.getAddress(),4),c(0xffffbfffL,4));}
                    b.jump(PcodeOp.BRANCH,"exit",null);
                    continue;
                }
                nextPc=landing.target();
            }
            // SPRUFE8B 7.14: a taken branch idles a non-reloading buffer
            // after its five delay slots. Effects already issued still mature.
            boolean loopRedirect=landing!=null;
            LoopFrame normal=null,stopped=null;Varnode loopTest=null;boolean decrementOnContinue=true;long stoppedPc=nextPc;
            if(loopStart!=null){long startPc=loopStart.instruction().getAddress().getOffset();normal=new LoopFrame(startPc,0,-1,false,false,false);
                if(loopStart.name().equals("SPLOOP")){loopTest=ilcBefore;stopped=new LoopFrame(startPc,0,0,true,false,false);}
                if(loopStart.name().equals("SPLOOPW"))for(int age=0;age<3;age++)b.op(PcodeOp.COPY,slot("while_condition",startPc,age,0,1),c(0,1));
            }else if(loop!=null&&!loopRedirect){
                int time=loopNextTime(loop,s.loop().time());int drain=s.loop().drain()<0?-1:s.loop().drain()+1;
                normal=loopFinished(loop,s.loop())?null:new LoopFrame(loop.start(),time,drain,s.loop().zero(),s.loop().refill()||s.loop().drain()<0&&s.loop().time()>=loop.cells().size()-1,s.loop().abrupt());
                if(!loop.kind().equals("SPLOOPW")&&s.loop().drain()<0&&(s.loop().time()+1)%loop.ii()==0&&(loop.kind().equals("SPLOOP")||s.loop().time()>=3)){
                    loopTest=counterBefore;stopped=new LoopFrame(loop.start(),time,1,false,s.loop().refill(),false);
                    if(loopFinished(loop,new LoopFrame(loop.start(),s.loop().time(),0,false,s.loop().refill(),false)))stopped=null;
                }
            }
            if(loop!=null&&!loopRedirect&&loop.kind().equals("SPLOOPW")&&!s.loop().abrupt()){
                // SPRUFE8B 7.10.2: sample the register visible before E1, three advances ago.
                var oldest=temp(1);b.op(PcodeOp.COPY,oldest,slot("while_condition",loop.start(),2,0,1));
                var one=temp(1);var two=temp(1);b.op(PcodeOp.COPY,one,slot("while_condition",loop.start(),0,0,1));b.op(PcodeOp.COPY,two,slot("while_condition",loop.start(),1,0,1));
                b.op(PcodeOp.COPY,slot("while_condition",loop.start(),0,0,1),whileSample);
                b.op(PcodeOp.COPY,slot("while_condition",loop.start(),1,0,1),one);b.op(PcodeOp.COPY,slot("while_condition",loop.start(),2,0,1),two);
                // Section 7.10 expressly says ILC/RILC are neither read nor modified.
                if((s.loop().time()+1)%loop.ii()==0&&s.loop().time()>=3){loopTest=oldest;decrementOnContinue=false;stopped=s.loop().refill()||s.loop().time()<loop.cells().size()-1?new LoopFrame(loop.start(),loopNextTime(loop,s.loop().time()),1,false,s.loop().refill(),true):null;stoppedPc=sourceFetch?nextPc:loop.postPc();}
            }
            if(loopRedirect){normal=null;stopped=null;}
            if(loopTest!=null){
                String stop="loop_stop_"+b.labelCounter++;var zero=temp(1);b.op(PcodeOp.INT_EQUAL,zero,loopTest,c(0,loopTest.getSize()));b.jump(PcodeOp.CBRANCH,stop,zero);if(decrementOnContinue){b.op(PcodeOp.INT_SUB,ilc(),loopTest,c(1,4));b.op(PcodeOp.COPY,new Varnode(program.getRegister("ILC").getAddress(),4),ilc());}
                emitTransfer(nextPc,idle,nextFlights,nextBranches,hazards,normal,issueBranch,captured,issued,loop!=null||loopStart!=null,loop!=null&&bufferFinished(loop,s.loop()));
                b.label(stop);emitTransfer(stoppedPc,idle,nextFlights,nextBranches,hazards,stopped,issueBranch,captured,issued,loop!=null||loopStart!=null,loop!=null&&bufferFinished(loop,s.loop()));
            }else emitTransfer(nextPc,idle,nextFlights,nextBranches,hazards,normal,issueBranch,captured,issued,loop!=null||loopStart!=null,loop!=null&&bufferFinished(loop,s.loop()));

        }
        b.label("exit");
        b.op(PcodeOp.RETURN,null,new Varnode(program.getRegister("C6000_PIPE_RET").getAddress(),4));
        var code=b.finish();
        Map<Integer,Integer> stalls=new LinkedHashMap<>();
        for(var e:stallLabels.entrySet())stalls.put(e.getKey(),b.labels.get(e.getValue()));
        return new Result(code,states.size(),packets,covered,Map.copyOf(cycleStarts),Map.copyOf(stalls));
    }

    private Varnode ilc(){return new Varnode(program.getRegister("C6000_PIPE_ILC").getAddress(),4);}

    private void emitTransfer(long pc,int idle,List<Flight> flights,List<Branch> branches,List<Hazard> hazards,LoopFrame loop,Insn issueBranch,Map<Long,Map<Long,Varnode>> captured,Map<Long,Eval> issued,boolean updateLoopStatus,boolean finishedCurrentBuffer){
        if(updateLoopStatus){var tsr=new Varnode(program.getRegister("TSR").getAddress(),4);boolean active=loop!=null&&!loop.abrupt()&&!finishedCurrentBuffer;b.op(active?PcodeOp.INT_OR:PcodeOp.INT_AND,tsr,tsr,c(active?0x4000:0xffffbfffL,4));}
        State noBranch=new State(pc,idle,List.copyOf(flights),List.copyOf(branches),List.copyOf(hazards),loop);
        if(issueBranch==null){b.jump(PcodeOp.BRANCH,"node"+state(noBranch),null);return;}
        var instruction=issueBranch.instruction();long at=instruction.getAddress().getOffset();var register=instruction.getRegister(0);boolean returns=register!=null&&register.getName().equals("B3");
        if(register!=null&&!returns)throw fail("unresolved register branch "+instruction);
        long target=returns?0:instruction.getAddress(0).getOffset();
        if(returns)b.op(PcodeOp.COPY,slot("target",at,1,0,4),captured.get(at).get(register.getAddress().getOffset()));
        List<Branch> yes=new ArrayList<>(branches);yes.add(new Branch(at,1,target,returns));State taken=new State(pc,idle,List.copyOf(flights),List.copyOf(yes),List.copyOf(hazards),loop);
        if(issueBranch.predicate()==null)b.jump(PcodeOp.BRANCH,"node"+state(taken),null);
        else{b.jump(PcodeOp.CBRANCH,"node"+state(taken),issued.get(at).predicate());b.jump(PcodeOp.BRANCH,"node"+state(noBranch),null);}
    }

    private void validateUnits(List<Insn> packet){
        Map<Integer,Insn> used=new HashMap<>();
        for(var instruction:packet){int unit=unit(instruction);if(unit==0)continue;var prior=used.putIfAbsent(unit,instruction);if(prior==null)continue;
            if(prior.predicate()!=null&&prior.predicate().equals(instruction.predicate())&&prior.inverted()!=instruction.inverted())continue;
            throw fail("functional-unit collision between "+prior.instruction()+" and "+instruction.instruction());
        }
    }

    private int unit(Insn instruction){
        // Displacement BNOP has no functional unit (SPRUFE8B 7.7.3.3).
        if(instruction.name().equals("BNOP")&&instruction.instruction().getAddress(0)!=null)return 0;
        Matcher match=Pattern.compile("\\.([LSDM])([12])").matcher(instruction.instruction().getMnemonicString());
        if(!match.find())return 0;return 1<<("LSDM".indexOf(match.group(1))*2+Integer.parseInt(match.group(2))-1);
    }

    private LoopPlan planLoop(Insn start)throws Exception{
        long at=start.instruction().getAddress().getOffset();if(loopPlans.containsKey(at))return loopPlans.get(at);
        int ii=(int)start.instruction().getScalar(0).getValue();if(ii<1||ii>14)throw fail("invalid loop interval");
        List<Insn> entryPacket=packet(at);long pc=after(entryPacket.get(entryPacket.size()-1));List<LoopCell> cells=new ArrayList<>();boolean found=false;int fetchDelay=0;
        while(cells.size()<48){
            List<Insn> instructions=packet(pc);int mask=0,duration=1;boolean kernel=false;
            for(var instruction:instructions){
                if(instruction.name().startsWith("SPLOOP"))throw fail("nested loop source without SPKERNEL");
                if(instruction.name().equals("SPMASK"))mask|=(int)instruction.instruction().getScalar(0).getValue();
                if(instruction.name().equals("SPKERNEL")){
                    kernel=true;int raw=(int)instruction.instruction().getScalar(0).getValue();int bits=ii==1?0:ii==2?1:ii<=4?2:ii<=8?3:4;int cycle=raw&((1<<bits)-1),stage=0;
                    for(int bit=0;bit<6-bits;bit++)stage|=((raw>>>(5-bit))&1)<<bit;fetchDelay=stage*ii+cycle;
                }
                duration=Math.max(duration,instruction.span());
            }
            List<Insn> buffered=new ArrayList<>();for(var instruction:instructions)if(!Set.of("SPKERNEL","SPMASK").contains(instruction.name())&&(unit(instruction)&mask)==0&&!instruction.name().equals("BNOP")){
                if(Set.of("B","MVC","ADDKPC").contains(instruction.name()))throw fail("unmasked control instruction in software loop buffer");buffered.add(instruction);
            }
            long next=after(instructions.get(instructions.size()-1));cells.add(new LoopCell(List.copyOf(instructions),List.copyOf(buffered),mask,next));for(int t=1;t<duration;t++)cells.add(new LoopCell(List.of(),List.of(),0,next));pc=next;
            if(kernel){found=true;break;}
        }
        if(!found||cells.size()>48)throw fail("loop source exceeds 48 dynamic cycles or lacks SPKERNEL");
        if(cells.size()<(start.name().equals("SPLOOPW")?ii:ii+1))throw fail("loop dynamic length below documented minimum");
        int cap=((Math.max(cells.size(),4)+ii-1)/ii)*ii;var plan=new LoopPlan(at,start.name(),ii,fetchDelay,cap,List.copyOf(cells),pc);loopPlans.put(at,plan);return plan;
    }

    private int loopNextTime(LoopPlan plan,int time){int next=time+1;return next>=plan.cap()+plan.ii()?next-plan.ii():next;}
    private int lastLoadingBoundary(LoopPlan plan){return ((plan.cells().size()+plan.ii()-1)/plan.ii())*plan.ii()-1;}
    // SPRUFE8B 7.9.5: both zero- and one-iteration invocations remain
    // active through the final loading stage boundary, even after SPKERNEL.
    private boolean singleIteration(LoopPlan plan,LoopFrame frame){return frame.drain()>=0&&frame.time()-frame.drain()<plan.ii();}
    private boolean bufferFinished(LoopPlan plan,LoopFrame frame){
        if(frame.abrupt())return true;if(frame.drain()<0)return false;
        if(frame.zero()||singleIteration(plan,frame))return frame.time()>=lastLoadingBoundary(plan);
        return frame.time()>=plan.cells().size()-1&&frame.drain()>=Math.max(0,plan.cells().size()-plan.ii());
    }
    private boolean loopFinished(LoopPlan plan,LoopFrame frame){
        if(frame.abrupt()&&!frame.refill())return frame.time()>=plan.cells().size()-1;
        if(!bufferFinished(plan,frame))return false;
        if(frame.zero())return true;
        var next=new LoopFrame(frame.start(),loopNextTime(plan,frame.time()),frame.drain()+1,false,frame.refill(),frame.abrupt());
        return postFetch(plan,frame)||postFetch(plan,next);
    }
    private boolean postFetch(LoopPlan plan,LoopFrame frame){
        if(frame.zero()||frame.drain()<0||singleIteration(plan,frame)&&frame.time()<=lastLoadingBoundary(plan))return false;
        // When program fetch stopped at the kernel, PG->PS->PW->PR->DP->DC
        // must refill before a resumed program packet reaches E1 (4.1.4).
        if(frame.abrupt())return frame.drain()>=7;
        int delay=Math.min(plan.fetchDelay(),Math.max(0,plan.cells().size()-plan.ii()))+(frame.refill()?6:0);
        return frame.time()>=plan.cells().size()&&frame.drain()>=1+delay;
    }
    private List<Insn> loopOperations(LoopPlan plan,LoopFrame frame,List<Insn> fetched){
        if(frame.abrupt())return fetched;
        List<Insn> result=new ArrayList<>();int mask=0;for(var instruction:fetched)if(instruction.name().equals("SPMASK"))mask|=(int)instruction.instruction().getScalar(0).getValue();
        for(var instruction:fetched)if(!frame.zero()||(unit(instruction)&mask)!=0||instruction.name().equals("BNOP")&&instruction.instruction().getAddress(0)!=null)result.add(instruction);
        for(int source=frame.time()%plan.ii();source<=frame.time()&&source<plan.cells().size();source+=plan.ii()){
            if(frame.zero()||source==frame.time()||frame.drain()>=0&&source<frame.drain())continue;
            for(var instruction:plan.cells().get(source).buffered())if((unit(instruction)&mask)==0)result.add(instruction);
        }
        return result;
    }

    private void checkStable(Insn instruction,int phase,List<Dest> writes){
        for(var read:instruction.reads())if(phase>=read.first()&&phase<read.last())for(var write:writes)
            if(write.offset()<read.offset()+4&&write.offset()+write.size()>read.offset())
                throw fail("writer violates repeated DP source-read stability at "+instruction.instruction().getAddress());
    }

    private void copy(List<Runnable> moves,Varnode to,Varnode from){
        var snapshot=temp(from.getSize());
        b.op(PcodeOp.COPY,snapshot,from);
        moves.add(()->b.op(PcodeOp.COPY,to,snapshot));
    }
    private final class Builder {
        List<PcodeOp> code=new ArrayList<>();
        Map<String,Integer> labels=new HashMap<>();
        Map<Integer,String> patches=new HashMap<>();
        int labelCounter;
        void op(int opcode,Varnode out,Varnode... inputs){
            if (code.size() >= 1000000) throw fail("scheduled p-code exceeds one million operations");
            code.add(new PcodeOp(entry,code.size(),opcode,inputs,out));
        }
        void label(String label){
            if(labels.put(label,code.size())!=null)throw fail("duplicate p-code label "+label);
        }
        void jump(int opcode,String target,Varnode condition){
            patches.put(code.size(),target);
            if(condition==null)op(opcode,null,c(0,4));
            else op(opcode,null,c(0,4),condition);
        }
        PcodeOp[] finish(){
            for(var p:patches.entrySet()){
                Integer target=labels.get(p.getValue());
                if(target==null)throw fail("missing p-code label "+p.getValue());
                code.get(p.getKey()).setInput(c(target-p.getKey(),4),0);
            }
            return code.toArray(PcodeOp[]::new);
        }
    }
}
