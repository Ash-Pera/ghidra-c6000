// SPDX-License-Identifier: Apache-2.0
package c6000;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.*;
public class C6000PipelineInjectLibrary extends PcodeInjectLibrary {

    public C6000PipelineInjectLibrary(SleighLanguage language){
        super(language);
    }

    public C6000PipelineInjectLibrary(C6000PipelineInjectLibrary other){
        super(other);
    }
    @Override public PcodeInjectLibrary clone(){
        return new C6000PipelineInjectLibrary(this);
    }
    @Override public InjectPayload allocateInject(String source,String name,int type){
        if(type==InjectPayload.CALLOTHERFIXUP_TYPE&&name.equals("c6000_pipeline"))return new C6000PipelinePayload(source);
        return super.allocateInject(source,name,type);
    }
}
