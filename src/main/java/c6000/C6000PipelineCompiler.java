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
* E1 operand capture, memory at E3, delayed writeback, and branch landing C+6.
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

    private record State(long pc,int idle,List<Flight> flights,List<Branch> branches,List<Hazard> hazards){
    }

    private record Dest(long offset,int size,boolean flags){
    }

    private record Insn(Instruction instruction,String name,PcodeOp[] raw,List<Long> regs,List<Dest> outputs,int latency,int span,boolean load,boolean store,Register predicate,boolean inverted){
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
    private final LinkedHashMap<State,Integer> states=new LinkedHashMap<>();
    private final Map<String,Varnode> slots=new HashMap<>();
    private final AddressSet covered=new AddressSet();

    private long nextUnique=0x10000000;

    private int packets;
    private final Map<Integer,Long> cycleStarts=new LinkedHashMap<>();
    private final Map<Integer,String> stallLabels=new LinkedHashMap<>();
    private static final Set<String> SINGLE=Set.of("ADD","ADDK","ADDAW","ADDAD","ADDAH","ADDAB","SUBAW","SUBAH","SUBAB","SUB","AND","OR","XOR","NOT","MV","MVK","MVKH","MVKL","MVKLH","SHL","SHR","SHRU","EXT","EXTU","SET","CLR","CMPEQ","CMPGT","CMPLT","CMPGTU","CMPLTU","ZERO","NEG","ABS","NORM","LMBD","ABSSP");

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
        String n=i.getMnemonicString();
        int j=n.indexOf(']');
        if(j>=0)n=n.substring(j+1);
        if(n.startsWith("_"))n=n.substring(1);
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
        else if(Set.of("ADDSP","SUBSP","MPYSP").contains(name))latency=4;
        else if(Set.of("MPY","MPYSU","MPYU","MPYUS").contains(name))latency=2;
        else if(name.equals("MVC")){
            latency=1;
            Set<String> ordinary=Set.of("AMR","CSR","FADCR","FAUCR","FMCR");
            for(int operand=0;operand<ins.getNumOperands();operand++) {
                for(Object object:ins.getOpObjects(operand)) if(object instanceof Register register) {
                    String registerName=register.getName();
                    if(!registerName.matches("[AB]([0-9]|[12][0-9]|3[01])")&&!ordinary.contains(registerName))                         throw fail("unimplemented control-register phase contract at "+at+": "+registerName);
                }
            }
        }
        else if(SINGLE.contains(name)||Set.of("NOP","B","BNOP","ADDKPC").contains(name))latency=1;
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
        var raw=ins.getPcode(false);
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
                destinations.put(out.getOffset()+":"+out.getSize(),new Dest(out.getOffset(),out.getSize(),flags));
            }
        }
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
        var desc=new Insn(ins,name,raw,List.copyOf(regs),List.copyOf(destinations.values()),latency,span,load,store,pred,inverted);
        instructions.put(pc,desc);
        return desc;
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

    private Eval evaluate(Insn i,Integer age,boolean actualMemory)throws Exception{
        long pc=i.instruction().getAddress().getOffset(),img=image();
        for(long off:i.regs())b.op(PcodeOp.COPY,im(img,off,4),age==null?arch(off,4):slot("input",pc,age,off,4));
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

    private void commit(Insn i,Eval eval,boolean dataOnly)throws Exception{
        String end="commit"+b.labelCounter++;
        b.jump(PcodeOp.CBRANCH,end,not(eval.predicate()));
        for(var d:i.outputs())if(dataDest(i,d)==dataOnly){
            Varnode value=d.flags()?eval.flags().get(d.offset()):im(eval.image(),d.offset(),d.size());
            if (d.flags()) b.op(PcodeOp.INT_OR, arch(d.offset(),d.size()), arch(d.offset(),d.size()), value);
            else b.op(PcodeOp.COPY, arch(d.offset(),d.size()), value);
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
        for(var d:i.outputs())if(!d.flags()&&(i.latency()==1||((i.load()||i.store())&&!dataDest(i,d))))for(long off=d.offset()&~3L;off<d.offset()+d.size();off+=4)if(off<0x2000)r.add(off);
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
        List<Hazard> incoming=List.of();
        if(!entryWrites.isEmpty()){
            // The preceding E1 packet is outside this function. Its writes are already
            // visible, but an X-path reader can still incur one pipeline-wide stall.
            incoming=List.of(new Hazard(-1,entryWrites));
            b.op(PcodeOp.COPY,slot("hazard",-1,0,0,1),c(1,1));
        }
        State start=new State(entry.getOffset(),0,List.of(),List.of(),incoming);
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
            List<Insn> pack=s.idle()>0?List.of():packet(s.pc());
            if(!pack.isEmpty())packets++;
            Set<Long> crosses=crossReads(pack);
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
                String target="node"+state(new State(s.pc(),s.idle(),s.flights(),s.branches(),List.of()));
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
                Eval e=evaluate(i,null,false);
                issued.put(pc,e);
                span=Math.max(span,i.span());
                if(i.name().equals("B")||i.name().equals("BNOP")){
                    if(issueBranch!=null)throw fail("multiple branches in a packet");
                    issueBranch=i;
                }
            }
            // All E1 operand reads precede writeback; memory operations mature on E3.
            Map<Flight,Eval> mature=new LinkedHashMap<>();
            for(var f:s.flights())if(f.age()==2&&decode(f.pc()).load())mature.put(f,evaluate(decode(f.pc()),f.age(),true));
            for(var f:s.flights())if(f.age()==2&&decode(f.pc()).store())mature.put(f,evaluate(decode(f.pc()),f.age(),true));
            for(var f:s.flights()){
                var i=decode(f.pc());
                if(i.load()&&f.age()==i.latency()-1||!i.load()&&!i.store()&&f.age()==i.latency()-1){
                    Map<Long,Varnode> flags=new LinkedHashMap<>();
                    long img=image();
                    for(var d:i.outputs())if(dataDest(i,d)){
                        var v=slot("output",f.pc(),f.age(),d.offset(),d.size());
                        if(d.flags())flags.put(d.offset(),v);
                        else b.op(PcodeOp.COPY,im(img,d.offset(),d.size()),v);
                    }
                    commit(i,new Eval(img,slot("predicate",f.pc(),f.age(),0,1),flags),true);
                }
            }
            for(var i:pack){
                var e=issued.get(i.instruction().getAddress().getOffset());
                if(i.load()||i.store())commit(i,e,false);
                else if(i.latency()==1)commit(i,e,true);
            }
            List<Flight> nextFlights=new ArrayList<>();
            List<Runnable> moves=new ArrayList<>();
            for(var f:s.flights()){
                var i=decode(f.pc());
                if(f.age()>=i.latency()-1)continue;
                int age=f.age()+1;
                nextFlights.add(new Flight(f.pc(),age));
                copy(moves,slot("predicate",f.pc(),age,0,1),slot("predicate",f.pc(),f.age(),0,1));
                for(long off:i.regs())copy(moves,slot("input",f.pc(),age,off,4),slot("input",f.pc(),f.age(),off,4));
                for(var d:i.outputs())if(dataDest(i,d)&&!i.store()&&(!i.load()||f.age()>=2)){
                    var e=mature.get(f);
                    Varnode from=e==null?slot("output",f.pc(),f.age(),d.offset(),d.size()):d.flags()?e.flags().get(d.offset()):im(e.image(),d.offset(),d.size());
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
                    if(!i.load()&&!i.store())for(var d:i.outputs())copy(moves,slot("output",pc,1,d.offset(),d.size()),d.flags()?e.flags().get(d.offset()):im(e.image(),d.offset(),d.size()));
                }
            }
            long nextPc=pack.isEmpty()?s.pc():after(pack.get(pack.size()-1));
            int idle=pack.isEmpty()?s.idle()-1:span-1;
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
                    b.jump(PcodeOp.BRANCH,"exit",null);
                    continue;
                }
                nextPc=landing.target();
            }
            State noBranch=new State(nextPc,idle,List.copyOf(nextFlights),List.copyOf(nextBranches),List.copyOf(hazards));
            if(issueBranch==null)b.jump(PcodeOp.BRANCH,"node"+state(noBranch),null);
            else{
                var bi=issueBranch.instruction();
                long pc=bi.getAddress().getOffset();
                var reg=bi.getRegister(0);
                boolean returns=reg!=null&&reg.getName().equals("B3");
                if(reg!=null&&!returns)throw fail("unresolved register branch "+bi);
                var target=returns?0:bi.getAddress(0).getOffset();
                if(returns)b.op(PcodeOp.COPY,slot("target",pc,1,0,4),captured.get(pc).get(reg.getAddress().getOffset()));
                List<Branch> yes=new ArrayList<>(nextBranches);
                yes.add(new Branch(pc,1,target,returns));
                State taken=new State(nextPc,idle,List.copyOf(nextFlights),List.copyOf(yes),List.copyOf(hazards));
                if(issueBranch.predicate()==null)b.jump(PcodeOp.BRANCH,"node"+state(taken),null);
                else{
                    b.jump(PcodeOp.CBRANCH,"node"+state(taken),issued.get(pc).predicate());
                    b.jump(PcodeOp.BRANCH,"node"+state(noBranch),null);
                }
            }
        }
        b.label("exit");
        b.op(PcodeOp.RETURN,null,new Varnode(program.getRegister("C6000_PIPE_RET").getAddress(),4));
        var code=b.finish();
        Map<Integer,Integer> stalls=new LinkedHashMap<>();
        for(var e:stallLabels.entrySet())stalls.put(e.getKey(),b.labels.get(e.getValue()));
        return new Result(code,states.size(),packets,covered,Map.copyOf(cycleStarts),Map.copyOf(stalls));
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
