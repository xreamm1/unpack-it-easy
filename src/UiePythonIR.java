import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.GsonBuilder;
import java.util.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

/** Static typed SSA export: evidence for reconstruction, never claimed to be Python source. */
public class UiePythonIR extends HeadlessScript {
    private static final int TIMEOUT=45, MAX_OPS=32768, MAX_NODES=65536;
    private final IdentityHashMap<Varnode,String> ids=new IdentityHashMap<>();
    private final List<Map<String,Object>> nodes=new ArrayList<>();
    private Map<String,Object> row(Object...pairs) {
        Map<String,Object> result=new LinkedHashMap<>();
        for(int i=0;i<pairs.length;i+=2)result.put((String)pairs[i],pairs[i+1]);
        return result;
    }
    private String node(Varnode value) {
        if(value==null)return null;
        if(ids.containsKey(value))return ids.get(value);
        if(nodes.size()>=MAX_NODES)throw new IllegalStateException("SSA node budget exceeded");
        String id="v"+nodes.size();ids.put(value,id);
        Map<String,Object> record=row("id",id,"size",value.getSize(),"space",value.getAddress().getAddressSpace().getName(),"offset",Long.toUnsignedString(value.getOffset(),16),"constant",value.isConstant(),"input",value.isInput());
        if(value instanceof VarnodeAST) {
            HighVariable variable=((VarnodeAST)value).getHigh();
            if(variable!=null) { record.put("decompiler_name",variable.getName());record.put("type",variable.getDataType().getName()); }
        }
        nodes.add(record);return id;
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=3||!args[1].matches("[a-fA-F0-9]{1,16}")||!args[2].matches("[a-fA-F0-9]{1,16}"))throw new IllegalArgumentException("Expected output, entry and exclusive end");
        Address start=toAddr(args[1]),end=toAddr(args[2]);
        if(end.compareTo(start)<=0||end.subtract(start)>262144)throw new IllegalArgumentException("Invalid or oversized function extent");
        Function function=getFunctionAt(start);
        if(function==null) {
            AddressSet body=new AddressSet(start,end.subtract(1));
            DisassembleCommand decode=new DisassembleCommand(start,body,true);decode.enableCodeAnalysis(false);
            if(!decode.applyTo(currentProgram,monitor))throw new IllegalStateException(decode.getStatusMsg());
            function=currentProgram.getFunctionManager().createFunction("FUN_"+args[1],start,body,SourceType.ANALYSIS);
        }
        println("UIE runtime compiler spec: "+currentProgram.getCompilerSpec().getCompilerSpecID());
        int runtimeFixups=UieNativeRuntime.apply(currentProgram,new AddressSet(start,end.subtract(1)));
        if(runtimeFixups>0)println("UIE verified MSVC runtime fixups: "+runtimeFixups);
        DecompInterface decompiler=new DecompInterface();
        try {
            if(!decompiler.openProgram(currentProgram))throw new IllegalStateException("Cannot open program");
            DecompileResults result=decompiler.decompileFunction(function,TIMEOUT,monitor);
            if(!result.decompileCompleted()||result.getHighFunction()==null)throw new IllegalStateException(result.getErrorMessage());
            export(currentProgram,result.getHighFunction(),Paths.get(args[0]));
            Files.writeString(Paths.get(args[0]+".c"),result.getDecompiledFunction().getC(),StandardCharsets.UTF_8);
        } finally {decompiler.dispose();}
    }
    public static void export(Program program,HighFunction high,Path output) throws Exception {
        new UiePythonIR().collect(program,high,output);
    }
    private void collect(Program program,HighFunction high,Path output) throws Exception {
        Function function=high.getFunction();
            List<Map<String,Object>> operations=new ArrayList<>(),blocks=new ArrayList<>();
            Iterator<PcodeOpAST> iterator=high.getPcodeOps();
            while(iterator.hasNext()) {
                if(Thread.currentThread().isInterrupted())throw new InterruptedException("SSA export cancelled");
                if(operations.size()>=MAX_OPS)throw new IllegalStateException("SSA operation budget exceeded");
                PcodeOpAST op=iterator.next();
                List<String> inputs=new ArrayList<>();for(int i=0;i<op.getNumInputs();i++)inputs.add(node(op.getInput(i)));
                Map<String,Object> record=row("id","op"+operations.size(),"instruction",op.getSeqnum().getTarget().toString(),"sequence",op.getSeqnum().getTime(),"opcode",op.getMnemonic(),"block",op.getParent().getIndex(),"output",node(op.getOutput()),"inputs",inputs);
                if(op.getOpcode()==PcodeOp.CALL) {
                    Address target=op.getInput(0).getAddress();
                    if(op.getInput(0).isConstant())target=program.getAddressFactory().getDefaultAddressSpace().getAddress(op.getInput(0).getOffset());
                    Function callee=program.getFunctionManager().getFunctionAt(target);
                    if(callee!=null&&callee.isThunk())callee=callee.getThunkedFunction(true);
                    ghidra.program.model.symbol.Symbol symbol=program.getSymbolTable().getPrimarySymbol(target);
                    String name=callee!=null?callee.getName():symbol!=null?symbol.getName():target.toString();
                    for(ghidra.program.model.symbol.Reference reference:program.getReferenceManager().getReferencesFrom(target)) {
                        if(reference.isExternalReference()) {
                            ghidra.program.model.symbol.ExternalLocation external=((ghidra.program.model.symbol.ExternalReference)reference).getExternalLocation();
                            if(external!=null) {name=external.getLabel();record.put("external_library",external.getLibraryName());break;}
                        }
                    }
                    record.put("callee",name);
                    record.put("callee_origin",callee!=null?"function":symbol!=null?"symbol":"address");
                    record.put("argument_count",op.getNumInputs()-1);
                }
                operations.add(record);
            }
            for(PcodeBlockBasic block:high.getBasicBlocks()) {
                List<Integer> successors=new ArrayList<>();for(int i=0;i<block.getOutSize();i++)successors.add(block.getOut(i).getIndex());
                List<Integer> predecessors=new ArrayList<>();for(int i=0;i<block.getInSize();i++)predecessors.add(block.getIn(i).getIndex());
                blocks.add(row("id",block.getIndex(),"start",block.getStart().toString(),"predecessors",predecessors,"successors",successors));
            }
            Map<String,Object> report=row("engine","UIE typed CPython semantic IR prototype","input_sha256",program.getExecutableSHA256(),"function",function.getName(),"entry",function.getEntryPoint().toString(),"function_end",function.getBody().getMaxAddress().toString(),"blocks",blocks,"values",nodes,"operations",operations,"target_executed",false,"python_body_recovered",false,"contract","Ghidra typed SSA and CFG evidence only. Decompiler-inferred calls and types are not proof of original Python semantics. Unknown indirect calls remain CALLIND. No operations or error paths intentionally removed.");
            Files.createDirectories(output.toAbsolutePath().getParent());
            Files.writeString(output,new GsonBuilder().setPrettyPrinting().create().toJson(report),StandardCharsets.UTF_8);

    }

}
