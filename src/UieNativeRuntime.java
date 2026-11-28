import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SourceType;
import java.util.*;

/** Recognizes one complete MSVC cookie-check success path; does not execute target code. */
public class UieNativeRuntime {
    private static final int[] BYTES={0x48,0x3b,0x0d,-1,-1,-1,-1,0x75,0x10,0x48,0xc1,0xc1,0x10,0x66,0xf7,0xc1,0xff,0xff,0x75,0x01,0xc3,0x48,0xc1,0xc9,0x10,0xe9,-1,-1,-1,-1};
    private static int signed32(byte[] bytes,int at){return (bytes[at]&255)|((bytes[at+1]&255)<<8)|((bytes[at+2]&255)<<16)|(bytes[at+3]<<24);}
    public static int apply(Program program,Function owner) throws Exception {return apply(program,owner.getBody());}
    public static int apply(Program program,AddressSetView body) throws Exception {
        if(program.getDefaultPointerSize()!=8||!program.getLanguage().getProcessor().toString().equals("x86")||!program.getCompilerSpec().getCompilerSpecID().toString().equals("windows"))return 0;
        Set<Address> targets=new HashSet<>();
        InstructionIterator instructions=program.getListing().getInstructions(body,true);
        while(instructions.hasNext()){
            Instruction instruction=instructions.next();
            if(instruction.getFlowType().isCall())for(Address target:instruction.getFlows())targets.add(target);
            if(targets.size()>4096)throw new IllegalStateException("Runtime call-target budget exceeded");
        }
        int applied=0;
        for(Address entry:targets){
            byte[] bytes=new byte[BYTES.length];
            try{if(program.getMemory().getBytes(entry,bytes)!=bytes.length)continue;}catch(MemoryAccessException error){continue;}
            boolean match=true;for(int i=0;i<BYTES.length;i++)if(BYTES[i]>=0&&(bytes[i]&255)!=BYTES[i]){match=false;break;}
            if(!match)continue;
            Address cookie,failure,codeEnd,cookieEnd;
            try {
                cookie=entry.addNoWrap(7L+signed32(bytes,3));
                failure=entry.addNoWrap(30L+signed32(bytes,26));
                codeEnd=entry.addNoWrap(29);cookieEnd=cookie.addNoWrap(7);
            } catch(AddressOverflowException error){continue;}
            MemoryBlock data=program.getMemory().getBlock(cookie),failed=program.getMemory().getBlock(failure),code=program.getMemory().getBlock(entry);
            if(data==null||!data.isInitialized()||data.isExecute()||!data.contains(cookieEnd)||failed==null||!failed.isExecute()||code==null||!code.isExecute()||!code.contains(codeEnd))continue;
            // Only the immediate Windows __fastfail(FAST_FAIL_STACK_COOKIE_CHECK_FAILURE) tail.
            // An arbitrary executable returning tail cannot justify erasing this call's behavior.
            byte[] fastfail=new byte[7];
            try {
                if(!failed.contains(failure.addNoWrap(6))||program.getMemory().getBytes(failure,fastfail)!=7)continue;
            } catch(AddressOverflowException|MemoryAccessException error){continue;}
            if(!Arrays.equals(fastfail,new byte[]{(byte)0xb9,2,0,0,0,(byte)0xcd,0x29}))continue;
            Function helper=program.getFunctionManager().getFunctionAt(entry);
            if(helper!=null&&helper.getSignatureSource()==SourceType.USER_DEFINED)continue;
            if(helper==null)helper=program.getFunctionManager().createFunction("uie_security_cookie_"+entry,entry,new AddressSet(entry,codeEnd),SourceType.ANALYSIS);
            if(helper==null)continue;
            helper.updateFunction(null,new ReturnParameterImpl(VoidDataType.dataType,program),Arrays.asList(new ParameterImpl("cookie",UnsignedLongLongDataType.dataType,program)),Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.ANALYSIS);
            helper.setCallFixup("security_check_cookie");applied++;
        }
        return applied;
    }
}
